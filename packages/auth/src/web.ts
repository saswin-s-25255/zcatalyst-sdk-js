import {
	clearStratusJwt,
	ConfigStore,
	getCredentials,
	JWT_COOKIE_PREFIX,
	setDefaultProjectConfig
} from '@zcatalyst/auth-client';
import { Handler, IRequestConfig, RequestType, ResponseType } from '@zcatalyst/transport';
import {
	CatalystService,
	Component,
	CONSTANTS,
	isNonEmptyString,
	isValidUrl,
	wrapValidatorsWithPromise
} from '@zcatalyst/utils';

import pkg from '../package.json';
const { version } = pkg;
import {
	AUTH_ERROR_MSG,
	AUTH_STATIC_FILES,
	CURRENT_CLIENT_PAGE_HOST,
	CURRENT_CLIENT_PAGE_PORT,
	CURRENT_CLIENT_PAGE_PROTOCOL,
	FETCH_DETAILS_CALLBACK_FN,
	JWT_FUNCTIONS_COOKIE_KEY,
	JWT_STRATUS_COOKIE_KEY,
	POPUP_DEFAULT_HEIGHT,
	POPUP_DEFAULT_TIMEOUT_MS,
	POPUP_DEFAULT_WIDTH,
	POPUP_LOGIN_PATH,
	POPUP_LOGOUT_PATH,
	POPUP_MSG_AUTH_ERROR,
	POPUP_MSG_AUTH_REQUEST,
	POPUP_MSG_AUTH_TOKEN,
	POPUP_MSG_SIGNOUT_DONE,
	POPUP_POLL_INTERVAL_MS,
	UM_URL_DIVIDER,
	URL_DIVIDER
} from './utils/constants';
import { Auth_Protocol } from './utils/enums';
import { CatalystAuthenticationError } from './utils/error';
import { wrapCheck } from './utils/functions';
import {
	ICatalystAuthResponse,
	ICatalystPopupSignInConfig,
	ICatalystPopupSignInResult,
	ICatalystSignInConfig,
	ICatalystSignUpConfig,
	IPopupAuthOperation,
	UserDetails
} from './utils/interface';
import { applyQueryString, hasSuffInfo } from './utils/validators';

const { CREDENTIAL_USER, REQ_METHOD, COMPONENT } = CONSTANTS;

/** Provides browser authentication flows for hosted sign-in, embedded sign-in, sign-up, and user profile access. */
class Authentication implements Component {
	requester: Handler;
	zaid: string = ConfigStore.get('ZAID') as string;
	projectId: string = ConfigStore.get('PROJECT_ID') as string;
	isAppsail: string = ConfigStore.get('IS_APPSAIL') as string;
	authProtocol: Auth_Protocol = ConfigStore.get('AUTH_PROTOCOL') as unknown as Auth_Protocol;
	/** Creates a browser authentication client for the provided Catalyst app. */
	constructor(app?: unknown) {
		this.requester = new Handler(app, this);
		getCredentials().catch(() => {
			// Credentials will be loaded on-demand or set via ConfigStore
		});
		this.signIn = this.signIn.bind(this);
		this.signOut = this.signOut.bind(this);
		this.isUserAuthenticated = this.isUserAuthenticated.bind(this);
	}

	/**
	 * Retrieves the name of the current component.
	 * @returns The name of the user management component.
	 */
	getComponentName(): string {
		return COMPONENT.user_management;
	}

	/** Retrieves the package version used by this component. */
	getComponentVersion(): string {
		return version;
	}

	/**
	 * Initializes the browser authentication component.
	 *
	 * @returns A promise that resolves when browser authentication initialization is complete.
	 *
	 * @example
	 * ```ts
	 * await zcAuth.init();
	 * ```
	 */
	async init(): Promise<void> {}

	/**
	 * Starts the embedded IAM sign-in flow inside a target DOM element or redirects an already authenticated user.
	 *
	 * @param id - DOM element ID where the login iframe should be mounted.
	 * @param config - Sign-in configuration.
	 *   - `redirectUrl`: URL to open after successful sign-in.
	 *   - `serviceUrl`: Service URL used as the post-login destination.
	 *   - `cssUrl`: Custom CSS URL for the sign-in page.
	 *   - `signInProvidersOnly`: Whether to show only configured federated sign-in providers.
	 *   - `forgotPasswordId`: DOM element ID where the forgot-password iframe should be mounted.
	 *   - `forgotPasswordCssUrl`: Custom CSS URL for the forgot-password page.
	 * @returns A promise that resolves after the sign-in iframe flow is prepared or a redirect is triggered.
	 * @throws {CatalystAuthenticationError} when the target DOM element cannot be found.
	 * @see {@link zcAuth} in `./node` for the Node.js authentication surface.
	 *
	 * @example
	 * ```ts
	 * import { zcAuth } from '@zcatalyst/auth';
	 *
	 * await zcAuth.signIn('login-container', { redirectUrl: '/dashboard' });
	 * ```
	 */
	async signIn(id: string, config: ICatalystSignInConfig = {}): Promise<void> {
		// If called inside a cross-origin iframe, the Catalyst IAM login page
		// cannot render due to CSP restrictions. Automatically fallback to
		// signInViaPopup() which opens login in a popup window instead.
		const isIframe = typeof window !== 'undefined' && window.self !== window.top;
		if (isIframe) {
			await this.signInViaPopup({
				width: config.popupWidth,
				height: config.popupHeight,
				timeoutMs: config.popupTimeoutMs
			});
			return;
		}
		try {
			const isValidUser = await this.#isValidUser();
			if (isValidUser) {
				window.location.href = this.#constructRedirectUrl(
					config.redirectUrl ?? config.serviceUrl ?? ''
				);
			} else {
				await this.#notSignedIn(id, config);
			}
		} catch {
			await this.#notSignedIn(id, config);
		}
	}

	/**
	 * Redirects the browser to the Catalyst hosted sign-in page.
	 *
	 * @param redirectUrl - URL to return to after a successful hosted sign-in.
	 * @returns A promise that resolves after credentials are available and the redirect is initiated.
	 * @see {@link zcAuth} in `./node` for the Node.js authentication surface.
	 *
	 * @example
	 * ```ts
	 * await zcAuth.hostedSignIn('/dashboard');
	 * ```
	 */
	async hostedSignIn(redirectUrl?: string): Promise<void> {
		if (!ConfigStore.get('INITIALIZED')) {
			await getCredentials();
		}
		window.location.href = `/${URL_DIVIDER.RESERVED_URL}/${URL_DIVIDER.AUTH}/${URL_DIVIDER.LOGIN}?redirect_url=${encodeURIComponent(redirectUrl ?? '/')}`;
	}

	/**
	 * Enables JWT token authentication and registers a callback to fetch user details.
	 *
	 * @param callbackFn - Callback invoked by the auth flow to fetch or refresh user details.
	 * @returns Nothing.
	 * @see {@link zcAuth} in `./node` for the Node.js authentication surface.
	 *
	 * @example
	 * ```ts
	 * zcAuth.signinWithJwt(() => {
	 *   void fetch('/api/current-user');
	 * });
	 * ```
	 */
	public signinWithJwt(callbackFn: () => void): void {
		ConfigStore.set(FETCH_DETAILS_CALLBACK_FN, callbackFn);
		ConfigStore.set('AUTH_PROTOCOL', Auth_Protocol.JwtTokenProtocol);
	}

	/**
	 * Retrieves the public sign-up configuration for the current Catalyst project.
	 *
	 * @returns A promise that resolves to the public sign-up settings response.
	 * @see {@link zcAuth} in `./node` for the Node.js authentication surface.
	 *
	 * @example
	 * ```ts
	 * const signupSettings = await zcAuth.publicSignup();
	 * console.log(signupSettings.data?.public_signup);
	 * ```
	 */
	async publicSignup(): Promise<ICatalystAuthResponse> {
		const appDomain = `${location.protocol}//${location.host}`;
		const request: IRequestConfig = {
			method: REQ_METHOD.get,
			url:
				appDomain +
				`/${URL_DIVIDER.RESERVED_URL}/${URL_DIVIDER.AUTH}/${URL_DIVIDER.PUBLIC_SIGNUP}`,
			type: RequestType.JSON,
			expecting: ResponseType.JSON, // text
			service: CatalystService.EXTERNAL
		};
		const resp = await this.requester.send(request);
		return resp.data;
	}

	//Normal styling for iframe
	#styleIFrame(iframe: HTMLIFrameElement): void {
		iframe.style.height = '100%';
		iframe.style.width = '100%';
		iframe.style.border = 'none';
	}

	#createIframeAndAttach(id: string, url: string) {
		const target: HTMLElement = document.getElementById(id) as HTMLElement;
		if (target === null) {
			throw new CatalystAuthenticationError(
				'AUTHENTICATION_ERROR',
				`Unable to get element with id : ${id}`
			); // TODO: throwing error here is crt
		} else {
			const iframe: HTMLIFrameElement = document.createElement('iframe');
			iframe.src = url;
			iframe.id = 'iam_iframe';
			this.#styleIFrame(iframe);
			target.innerHTML = '';
			target.appendChild(iframe);
			return iframe;
		}
	}

	#constructIAMIframeUrl(config: ICatalystSignInConfig, isPublicSignupEnabled: boolean) {
		const signInProvidersOnly = config.signInProvidersOnly;
		const hideForgotPassword = signInProvidersOnly ? true : false;
		const cssUrl: string =
			config.cssUrl ||
			applyQueryString(AUTH_STATIC_FILES.URL, {
				file_name: config.signInProvidersOnly
					? AUTH_STATIC_FILES.SIGNIN_WITH_PROVIDERS_ONLY
					: AUTH_STATIC_FILES.SIGNIN
			});
		// service url availbel in params
		const redirectUrl = new URLSearchParams(window.location.search).get(
			'service_url'
		) as string;
		const serviceUrl = config.redirectUrl ?? config.serviceUrl ?? redirectUrl;
		const appDomain = `${location.protocol}//${location.host}`;
		const signInRedirect = encodeURIComponent(this.#constructRedirectUrl(serviceUrl));

		const recoveryUrl = `${appDomain}/accounts/p/70-${this.zaid}/password?servicename=ZohoCatalyst&&serviceurl=${signInRedirect}`;

		const urlParams: Record<string, string | boolean> = {
			css_url: cssUrl,
			portal: this.zaid,
			servicename: 'ZohoCatalyst',
			serviceurl: encodeURIComponent(this.#constructRedirectUrl(serviceUrl)),
			hide_signup: true,
			hide_fs: `${!isPublicSignupEnabled}`,
			dcc: true,
			hide_fp: `${hideForgotPassword}`,
			recoveryurl: encodeURIComponent(recoveryUrl)
		};

		const params = Object.keys(urlParams)
			.map((key) => `${key}=${urlParams[key]}`)
			.join('&');
		const baseDomain = `${appDomain}/accounts/p/${this.zaid}/signin?${params}`;
		return baseDomain;
	}

	async #errorMsgHandler() {
		this.#attachMutationObserver(Authentication.#getEmailInpErrorDiv(), this.#trackErrorMsgCnt);
	}

	async #trackErrorMsgCnt(mutationList: Array<MutationRecord>, _observer: unknown) {
		for (const mutation of mutationList) {
			if (
				mutation.type === 'attributes' &&
				(mutation.target as HTMLElement).style.display === 'block'
			) {
				const errorDiv = Authentication.#getEmailInpErrorDiv() as HTMLElement;
				if (errorDiv.innerText.toLowerCase().includes(AUTH_ERROR_MSG.noAccountIncludes)) {
					errorDiv.innerText = AUTH_ERROR_MSG.noAccountMsg;
				}
			}
		}
	}

	static #getEmailInpErrorDiv() {
		const iframeElem = document.getElementById('iam_iframe') as HTMLIFrameElement;
		return iframeElem.contentDocument
			?.getElementById('login_id_container')
			?.querySelector('.fielderror');
	}

	#attachMutationObserver(
		elem?: Element | null,
		callbackFn?: (m: Array<MutationRecord>, o: unknown) => void,
		config = { attributes: true }
	) {
		if (callbackFn && elem) {
			// TODO: check this logic
			const observer = new MutationObserver(callbackFn);
			observer.observe(elem, config);
		}
	}

	/**
	 * Signs out the current browser user and redirects to the requested URL.
	 *
	 * @param redirectURL - URL to navigate to after sign-out.
	 * @returns A promise that resolves after the sign-out redirect is initiated.
	 * @see {@link zcAuth} in `./node` for the Node.js authentication surface.
	 *
	 * @example
	 * ```ts
	 * await zcAuth.signOut('/signed-out');
	 * ```
	 */
	async signOut(redirectURL = '/'): Promise<void> {
		setDefaultProjectConfig();
		if (this.authProtocol === Auth_Protocol.JwtTokenProtocol) {
			document.cookie = `${JWT_COOKIE_PREFIX}=; path=/; expires=${new Date().toUTCString()};`;
			document.cookie = `user_cred=; path=/; expires=${new Date().toUTCString()};`;
			clearStratusJwt();
			// Force immediate redirect for JWT
			window.location.replace(redirectURL);
			return;
		} else {
			if (this.isAppsail === 'true') {
				const validUser = await this.#isValidUser();
				if (!validUser) {
					if (redirectURL.startsWith('/')) {
						redirectURL =
							CURRENT_CLIENT_PAGE_PORT != ''
								? `${CURRENT_CLIENT_PAGE_PROTOCOL}//${CURRENT_CLIENT_PAGE_HOST}:${CURRENT_CLIENT_PAGE_PORT}${redirectURL}`
								: `${CURRENT_CLIENT_PAGE_PROTOCOL}//${CURRENT_CLIENT_PAGE_HOST}${redirectURL}`;
					}
					window.location.replace(redirectURL);
					return;
				}

				try {
					const request: IRequestConfig = {
						method: REQ_METHOD.get,
						url: this.#constructSignOutUrl(redirectURL),
						external: true
					};
					await this.requester.send(request);
					document.cookie = `CAUTH=; path=/accounts; expires=${new Date().toUTCString()};`;
					// Use replace instead of href for immediate navigation
					window.location.replace(redirectURL);
				} catch {
					// Use replace for error case too
					window.location.replace(this.#constructSignOutUrl(redirectURL));
				}
			} else {
				// Use replace instead of href for immediate navigation
				window.location.replace(this.#constructSignOutUrl(redirectURL));
			}
		}
	}

	#constructSignOutUrl(redirectURL: string): string {
		if (redirectURL.startsWith('/')) {
			redirectURL =
				CURRENT_CLIENT_PAGE_PORT != ''
					? `${CURRENT_CLIENT_PAGE_PROTOCOL}//${CURRENT_CLIENT_PAGE_HOST}:${CURRENT_CLIENT_PAGE_PORT}${redirectURL}`
					: `${CURRENT_CLIENT_PAGE_PROTOCOL}//${CURRENT_CLIENT_PAGE_HOST}${redirectURL}`;
		}
		return `/accounts/p/${this.zaid}/logout?servicename=ZohoCatalyst&serviceurl=${redirectURL}`;
	}

	async #notSignedIn(
		id: string,
		config: ICatalystSignInConfig
	): Promise<{ status?: number; content?: string }> {
		// Start the asynchronous operation
		const publicSignupResp: ICatalystAuthResponse = await this.publicSignup();
		const isPublicSignupEnabled = publicSignupResp.data?.public_signup as boolean;

		const signinIframe = this.#createIframeAndAttach(
			id,
			this.#constructIAMIframeUrl(config, isPublicSignupEnabled)
		);

		if (signinIframe) {
			signinIframe.onload = () => {
				const iframeElem = document.getElementById(
					'iam_iframe'
				) as HTMLIFrameElement | null;
				if (!iframeElem) return; // Ensure iframeElem exists

				const iframeDoc = iframeElem.contentWindow?.document;
				if (!iframeDoc) return; // Ensure iframeDoc exists

				const loginInpElem = iframeDoc.getElementById(
					'login_id'
				) as HTMLInputElement | null;
				if (loginInpElem) {
					loginInpElem.placeholder = AUTH_ERROR_MSG.emptyEmailAddress;
				}

				// Override values in I18N and error message handling
				this.#overrideValuesInI18N(iframeElem);
				this.#errorMsgHandler();

				if (config.signInProvidersOnly) {
					const fieldcontainer = iframeDoc.querySelector(
						'.fieldcontainer'
					) as HTMLElement | null;
					const signinContainer = iframeDoc.querySelector(
						'.signin_container'
					) as HTMLElement | null;
					const signinBox = iframeDoc.querySelector('.signin_box') as HTMLElement | null;

					if (fieldcontainer && signinContainer && signinBox) {
						fieldcontainer.style.display = 'none';
						signinContainer.style.minHeight = '320px';
						signinBox.style.minHeight = '320px';

						if (!iframeDoc.querySelector('.fed_2show')) {
							const divElem = document.createElement('div');
							divElem.innerText = 'No Social Logins available';
							fieldcontainer?.parentElement?.parentElement?.appendChild(divElem);
						}
					}
				}

				// Forgot password handler
				const forgotPasswordElem = iframeDoc.getElementById('forgotpassword');
				if (forgotPasswordElem) {
					const originalForgotPwd = forgotPasswordElem.querySelector(
						'a'
					) as HTMLElement | null;
					if (originalForgotPwd) {
						originalForgotPwd.onclick = () =>
							this.#forgotPasswordClickHandle(id, config);
					}

					const blueForgotPwd = iframeDoc.querySelectorAll(
						'#blueforgotpassword'
					) as NodeListOf<HTMLElement>;
					blueForgotPwd.forEach((btn) => {
						btn.onclick = () => this.#forgotPasswordClickHandle(id, config);
					});
				}

				// Resolve the promise with the status and content
				return { status: 200, content: 'success' }; // check is it resolvable resolve({})
			};
		}
		return {};
	}

	#overrideValuesInI18N(iframe: HTMLIFrameElement) {
		if (iframe.contentWindow?.I18N) {
			const IAMi18nData = (iframe.contentWindow?.I18N as { data?: Record<string, unknown> })
				?.data;
			if (IAMi18nData) {
				IAMi18nData['IAM.PHONE.ENTER.VALID.MOBILE_NUMBER'] =
					AUTH_ERROR_MSG.emptyEmailAddress;
				IAMi18nData['IAM.NEW.SIGNIN.ENTER.EMAIL.OR.MOBILE'] =
					AUTH_ERROR_MSG.emptyEmailAddress;
			}
		}
	}

	#forgotPasswordClickHandle(id: string, config: ICatalystSignInConfig) {
		const forgotPwdIframe = this.#createIframeAndAttach(
			config.forgotPasswordId ?? id,
			this.#getIAMForgotPasswordURL(config)
		);
		if (forgotPwdIframe) {
			forgotPwdIframe.onload = () => {
				const iframeElem: HTMLIFrameElement = document.getElementById(
					'iam_iframe'
				) as HTMLIFrameElement;
				const iframeDoc = iframeElem.contentWindow?.document as Document;
				const loginInpElem: HTMLInputElement = iframeDoc?.getElementById(
					'login_id'
				) as HTMLInputElement;
				loginInpElem.placeholder = AUTH_ERROR_MSG.emptyEmailAddress;
				this.#overrideValuesInI18N(iframeElem);
			};
		}
	}

	#getIAMForgotPasswordURL(config: ICatalystSignInConfig): string {
		const iframeElem: HTMLIFrameElement = document.getElementById(
			'iam_iframe'
		) as HTMLIFrameElement;
		const iframeDoc = iframeElem.contentWindow?.document;
		const loginInpElem: HTMLInputElement = iframeDoc?.getElementById(
			'login_id'
		) as HTMLInputElement;
		const cssUrl = config.forgotPasswordCssUrl
			? config.forgotPasswordCssUrl
			: applyQueryString(AUTH_STATIC_FILES.URL, { file_name: AUTH_STATIC_FILES.FORGOT_PWD });
		const queryParams = {
			css_url: cssUrl,
			portal: this.zaid,
			servicename: 'ZohoCatalyst',
			serviceurl: `${location.protocol}//${location.host}/`,
			hide_signup: true,
			dcc: true,
			LOGIN_ID: loginInpElem.value.toString()
		};
		const url = applyQueryString(
			`${location.protocol}//${location.host}/accounts/p/${this.zaid}/password`,
			queryParams
		);
		return url;
	}

	/**
	 * Registers a public user for the current Catalyst project.
	 *
	 * @param body - Sign-up details for the new user.
	 *   - `last_name`: Last name of the user.
	 *   - `email_id`: Email address of the user.
	 *   - `first_name`: Optional first name of the user.
	 *   - `platform_type`: Optional platform identifier, defaults to `web`.
	 *   - `redirect_url`: Optional URL to open after sign-up.
	 * @returns A promise that resolves to the sign-up API response data.
	 * @throws {CatalystAuthenticationError} when required sign-up details are missing or invalid.
	 * @see {@link zcAuth} in `./node` for the Node.js authentication surface.
	 *
	 * @example
	 * ```ts
	 * await zcAuth.signUp({
	 *   last_name: 'Patel',
	 *   email_id: 'maya.patel@example.com',
	 *   platform_type: 'web'
	 * });
	 * ```
	 */
	public async signUp(body: ICatalystSignUpConfig): Promise<unknown> {
		await wrapCheck((): void => {
			hasSuffInfo(body, ['last_name', 'email_id']);
		});
		const data: Record<string, unknown> = {};
		data.zaid = this.zaid as string;
		data.platform_type = (
			body.platform_type === undefined ? 'web' : body.platform_type
		) as string;
		if (body.redirect_url !== undefined) {
			data.redirect_url = body.redirect_url as string;
		}
		const userDetails: UserDetails = {};
		userDetails.last_name = body.last_name as string;
		userDetails.email_id = body.email_id as string;
		if (body.first_name !== undefined) {
			userDetails.first_name = body.first_name as string;
		}
		data.user_details = userDetails;
		const appDomain = `${location.protocol}//${location.host}`;
		const request: IRequestConfig = {
			method: REQ_METHOD.post,
			url: appDomain + `/__catalyst/${this.projectId}/auth/signup`,
			type: RequestType.JSON,
			data: data as Record<string, unknown>,
			service: CatalystService.EXTERNAL
		};
		const response = await this.requester.send(request);
		return response.data;
	}

	/**
	 * Checks whether a browser user is authenticated and returns user details when available.
	 *
	 * @param org_id - Optional organization ID used to validate the current user in a specific org.
	 * @returns A promise that resolves to the current user details or `false` when unauthenticated.
	 * @see {@link zcAuth} in `./node` for the Node.js authentication surface.
	 *
	 * @example
	 * ```ts
	 * const user = await zcAuth.isUserAuthenticated('123456789');
	 * if (user) console.log('Signed in');
	 * ```
	 */
	public async isUserAuthenticated(org_id?: string): Promise<unknown> {
		const resp = await this.getProjectUserDetails(org_id);
		if (resp.status === 'success') {
			return resp.data;
		} else {
			return false;
		}
	}

	#constructRedirectUrl(redirectUrl: string): string {
		const baseRedirectUrl = `${location.protocol}//${location.host}/__catalyst/${this.projectId}/auth/signin-redirect?PROJECT_ID=${this.zaid}`;
		if (
			redirectUrl &&
			!redirectUrl.includes(window.location.origin) &&
			!isValidUrl(redirectUrl)
		) {
			redirectUrl = `${window.location.origin}${redirectUrl}`;
		}
		return redirectUrl ? `${baseRedirectUrl}&service_url=${redirectUrl}` : baseRedirectUrl;
	}

	async #isValidUser(org_id?: string): Promise<Boolean> {
		const response = await this.getProjectUserDetails(org_id);
		if (response.status === 'success') {
			return true;
		}
		return false;
	}

	/**
	 * Retrieves the current project user details for the browser session.
	 *
	 * @param org_id - Optional organization ID used to scope the user lookup.
	 * @returns A promise that resolves to the project user details response.
	 * @see {@link zcAuth} in `./node` for the Node.js authentication surface.
	 *
	 * @example
	 * ```ts
	 * const details = await zcAuth.getProjectUserDetails();
	 * console.log(details.data);
	 * ```
	 */
	async getProjectUserDetails(org_id?: string): Promise<Record<string, unknown>> {
		const request: IRequestConfig = {
			method: REQ_METHOD.get,
			path: '/project-user/current',
			qs: org_id
				? {
						org_id
					}
				: {},
			type: RequestType.JSON,
			service: CatalystService.BAAS,
			track: true,
			user: CREDENTIAL_USER.user
		};
		const resp = await this.requester.send(request);
		return resp.data;
	}

	/**
	 * Changes the password for the currently authenticated browser user.
	 *
	 * @param oldPassword - Current password of the authenticated user.
	 * @param newPassword - New password to set for the authenticated user.
	 * @returns A promise that resolves to the change-password API response message.
	 * @throws {CatalystAuthenticationError} when either password value is empty or invalid.
	 * @see {@link zcAuth} in `./node` for the Node.js authentication surface.
	 *
	 * @example
	 * ```ts
	 * const message = await zcAuth.changePassword('old-password', 'new-password');
	 * ```
	 */
	async changePassword(oldPassword: string, newPassword: string): Promise<string> {
		await wrapValidatorsWithPromise(() => {
			isNonEmptyString(oldPassword, 'old_password', true);
			isNonEmptyString(newPassword, 'new_password', true);
		}, CatalystAuthenticationError);
		const changePasswordUrl = `/${UM_URL_DIVIDER.PROJECT_USER}/${URL_DIVIDER.CHANGE_PASSWORD}`;
		const request: IRequestConfig = {
			method: REQ_METHOD.put,
			path: changePasswordUrl,
			type: RequestType.JSON,
			qs: {
				old_password: oldPassword,
				new_password: newPassword
			},
			service: CatalystService.BAAS,
			track: true,
			user: CREDENTIAL_USER.user
		};
		const resp = await this.requester.send(request);
		return resp.data as unknown as string;
	}

	// ── Popup Auth ─────────────────────────────────────────────────────────────

	/** Active popup auth operation — one at a time, like Firebase's PopupOperation. */
	#popupAuthOperation: IPopupAuthOperation | null = null;
	#popupPollInterval: ReturnType<typeof setInterval> | null = null;
	#popupTimeoutHandle: ReturnType<typeof setTimeout> | null = null;
	#popupMessageListener: ((event: MessageEvent) => void) | null = null;

	/** Tears down all popup operation state after any outcome. */
	#clearPopupOperation(status: IPopupAuthOperation['status'] = 'cancelled'): void {
		if (this.#popupAuthOperation) {
			this.#popupAuthOperation.status = status;
			try {
				if (this.#popupAuthOperation.popup && !this.#popupAuthOperation.popup.closed) {
					this.#popupAuthOperation.popup.close();
				}
			} catch {
				/* ignore cross-origin close errors */
			}
			this.#popupAuthOperation.popup = null;
		}
		if (this.#popupPollInterval !== null) {
			clearInterval(this.#popupPollInterval);
			this.#popupPollInterval = null;
		}
		if (this.#popupTimeoutHandle !== null) {
			clearTimeout(this.#popupTimeoutHandle);
			this.#popupTimeoutHandle = null;
		}
		if (this.#popupMessageListener !== null) {
			window.removeEventListener('message', this.#popupMessageListener);
			this.#popupMessageListener = null;
		}
		this.#popupAuthOperation = null;
	}

	/** Opens a centered popup window. Throws if the browser blocks it. */
	#openPopupWindow(url: string, name: string, width: number, height: number): Window {
		const left = Math.round(window.screenX + (window.outerWidth - width) / 2);
		const top = Math.round(window.screenY + (window.outerHeight - height) / 2);
		const features = [
			`width=${width}`,
			`height=${height}`,
			`left=${left}`,
			`top=${top}`,
			'location=yes',
			'resizable=yes',
			'scrollbars=yes',
			'status=yes',
			'toolbar=no'
		].join(',');
		const popup = window.open(url, name, features);
		if (!popup) {
			throw new CatalystAuthenticationError(
				'POPUP_BLOCKED',
				'Popup was blocked by the browser. Please allow popups for this site and try again.'
			);
		}
		return popup;
	}

	/**
	 * Writes both JWT tokens into browser cookies.
	 *
	 * - functionsToken -> JWT_AUTH_TOKEN + JWT_AUTH (for API/Functions calls)
	 * - stratusToken   -> JWT_STRATUS_AUTH (for Stratus calls)
	 *
	 * Uses CHIPS partitioned cookies (cookieStore API) in a cross-origin iframe
	 * so tokens are sent on requests even with third-party cookie restrictions.
	 * Falls back to document.cookie on top-level pages.
	 */
	async #setJwtCookies(
		functionsToken: string,
		stratusToken: string,
		expiresInSec: number
	): Promise<void> {
		const isIframe = window.self !== window.top;
		const maxAge = expiresInSec > 0 ? expiresInSec : 3600;
		const cookieEntries: Array<{ key: string; value: string }> = [
			{ key: JWT_FUNCTIONS_COOKIE_KEY, value: functionsToken }, // JWT_AUTH_TOKEN
			{ key: JWT_COOKIE_PREFIX, value: functionsToken }, // JWT_AUTH (fallback)
			{ key: JWT_STRATUS_COOKIE_KEY, value: stratusToken } // JWT_STRATUS_AUTH
		];
		if (isIframe && 'cookieStore' in window) {
			const cs = (window as unknown as { cookieStore: CookieStore }).cookieStore;
			await Promise.all(
				cookieEntries.map(({ key, value }) =>
					cs.set({
						name: key,
						value,
						path: '/',
						expires: Date.now() + maxAge * 1000,
						secure: true,
						sameSite: 'none',
						partitioned: true
					} as CookieInit)
				)
			);
		} else {
			cookieEntries.forEach(({ key, value }) => {
				document.cookie = `${key}=${value}; max-age=${maxAge}; path=/; secure; samesite=none`;
			});
		}
	}

	/** Clears JWT cookies (CHIPS partitioned in iframe, standard on top-level). */
	async #clearJwtCookies(): Promise<void> {
		const isIframe = window.self !== window.top;
		const cookieKeys = [JWT_COOKIE_PREFIX, JWT_FUNCTIONS_COOKIE_KEY, JWT_STRATUS_COOKIE_KEY];
		if (isIframe && 'cookieStore' in window) {
			const cs = (window as unknown as { cookieStore: CookieStore }).cookieStore;
			await Promise.all(
				cookieKeys.map((key) =>
					cs.set({
						name: key,
						value: '',
						path: '/',
						expires: 0,
						secure: true,
						sameSite: 'none',
						partitioned: true
					} as CookieInit)
				)
			);
		} else {
			cookieKeys.forEach((key) => {
				document.cookie = `${key}=; max-age=0; path=/`;
			});
		}
		clearStratusJwt();
	}

	/**
	 * Signs in via a secure popup. Opens `/__catalyst/auth/login/popup`.
	 * The popup verifies the opener origin before generating any token.
	 * @example const { user } = await zcAuth.signInViaPopup();
	 */
	async signInViaPopup(
		config: ICatalystPopupSignInConfig = {}
	): Promise<ICatalystPopupSignInResult> {
		if (this.#popupAuthOperation && this.#popupAuthOperation.status === 'waiting') {
			throw new CatalystAuthenticationError(
				'POPUP_ALREADY_OPEN',
				'A sign-in popup is already open.'
			);
		}
		const width = config.width ?? POPUP_DEFAULT_WIDTH;
		const height = config.height ?? POPUP_DEFAULT_HEIGHT;
		const timeoutMs = config.timeoutMs ?? POPUP_DEFAULT_TIMEOUT_MS;
		const eventId = crypto.randomUUID();
		const popup = this.#openPopupWindow(
			`${window.location.origin}${POPUP_LOGIN_PATH}`,
			'catalystSignIn',
			width,
			height
		);
		this.#popupAuthOperation = { eventId, status: 'waiting', popup, createdAt: Date.now() };
		return new Promise<ICatalystPopupSignInResult>((resolve, reject) => {
			const onMessage = async (event: MessageEvent): Promise<void> => {
				if (!this.#popupAuthOperation || this.#popupAuthOperation.status !== 'waiting')
					return;
				if (event.origin !== window.location.origin) return;
				if (event.source !== this.#popupAuthOperation.popup) return;
				if (!event.data) return;
				if (event.data.type === POPUP_MSG_AUTH_ERROR) {
					this.#clearPopupOperation('cancelled');
					reject(
						new CatalystAuthenticationError(
							'POPUP_AUTH_ERROR',
							event.data.message ?? 'Sign-in failed.'
						)
					);
					return;
				}
				if (event.data.type !== POPUP_MSG_AUTH_TOKEN) return;
				if (event.data.eventId !== this.#popupAuthOperation.eventId) return;
				// Validate both tokens from the popup
				const functionsToken = event.data.tokens?.functions;
				const stratusToken = event.data.tokens?.stratus;
				if (
					typeof functionsToken !== 'string' ||
					!functionsToken ||
					functionsToken.length > 10000 ||
					typeof stratusToken !== 'string' ||
					!stratusToken ||
					stratusToken.length > 10000
				) {
					this.#clearPopupOperation('cancelled');
					reject(
						new CatalystAuthenticationError(
							'INVALID_TOKEN',
							'Popup sent missing or malformed tokens.'
						)
					);
					return;
				}
				this.#popupAuthOperation.status = 'completed';
				this.#clearPopupOperation('completed');
				try {
					const exp =
						typeof event.data.expires_in_sec === 'number' &&
						isFinite(event.data.expires_in_sec) &&
						event.data.expires_in_sec > 0 &&
						event.data.expires_in_sec < 86400 * 30
							? event.data.expires_in_sec
							: 3600;
					// Write both JWT tokens as cookies (CHIPS partitioned when in iframe)
					await this.#setJwtCookies(functionsToken, stratusToken, exp);
					const userResp = await this.getProjectUserDetails();
					resolve({
						user: userResp.data ?? userResp,
						tokens: { functions: functionsToken, stratus: stratusToken }
					});
				} catch (err) {
					reject(
						new CatalystAuthenticationError(
							'POST_AUTH_ERROR',
							err instanceof Error ? err.message : String(err)
						)
					);
				}
			};
			this.#popupMessageListener = onMessage;
			window.addEventListener('message', onMessage);
			this.#popupPollInterval = setInterval(() => {
				if (!this.#popupAuthOperation || this.#popupAuthOperation.status !== 'waiting') {
					this.#clearPopupOperation('cancelled');
					return;
				}
				if (this.#popupAuthOperation.popup?.closed) {
					this.#clearPopupOperation('cancelled');
					reject(
						new CatalystAuthenticationError(
							'POPUP_CLOSED',
							'Popup closed before auth completed.'
						)
					);
					return;
				}
				try {
					this.#popupAuthOperation.popup?.postMessage(
						{ type: POPUP_MSG_AUTH_REQUEST, eventId: this.#popupAuthOperation.eventId },
						window.location.origin
					);
				} catch {
					/* suppress during Zoho Accounts cross-origin redirect */
				}
			}, POPUP_POLL_INTERVAL_MS);
			this.#popupTimeoutHandle = setTimeout(() => {
				if (this.#popupAuthOperation && this.#popupAuthOperation.status === 'waiting') {
					this.#clearPopupOperation('expired');
					reject(
						new CatalystAuthenticationError(
							'POPUP_TIMEOUT',
							`Popup timed out after ${timeoutMs / 1000}s.`
						)
					);
				}
			}, timeoutMs);
		});
	}

	/**
	 * Signs out via a popup, fully invalidating the ADT/BDT server session.
	 * Opens `/__catalyst/auth/logout/popup` to hit the Zoho accounts logout URL.
	 * @example await zcAuth.signOutViaPopup();
	 */
	async signOutViaPopup(redirectUrl = '/'): Promise<void> {
		const popup = this.#openPopupWindow(
			`${window.location.origin}${POPUP_LOGOUT_PATH}`,
			'catalystSignOut',
			POPUP_DEFAULT_WIDTH,
			POPUP_DEFAULT_HEIGHT
		);
		return new Promise<void>((resolve, reject) => {
			const th = setTimeout(() => {
				window.removeEventListener('message', onMsg);
				try {
					if (!popup.closed) popup.close();
				} catch {
					/**/
				}
				reject(new CatalystAuthenticationError('POPUP_TIMEOUT', 'Sign-out timed out.'));
			}, POPUP_DEFAULT_TIMEOUT_MS);
			const onMsg = async (event: MessageEvent): Promise<void> => {
				if (event.origin !== window.location.origin) return;
				if (event.source !== popup) return;
				if (!event.data || event.data.type !== POPUP_MSG_SIGNOUT_DONE) return;
				clearTimeout(th);
				window.removeEventListener('message', onMsg);
				try {
					if (!popup.closed) popup.close();
				} catch {
					/**/
				}
				await this.#clearJwtCookies();
				document.cookie = `user_cred=; max-age=0; path=/`;
				if (redirectUrl) window.location.replace(redirectUrl);
				resolve();
			};
			window.addEventListener('message', onMsg);
		});
	}
}
export * from './utils/constants';

export const zcAuth = new Authentication();

declare global {
	interface Window {
		I18N?: {
			data?: Record<string, unknown>;
		};
	}
}

// ── CookieStore type shim ───────────────────────────────────────────────────
// Not yet in all TypeScript lib definitions — minimal shim keeps the build clean.
interface CookieInit {
	name: string;
	value: string;
	path?: string;
	expires?: number;
	secure?: boolean;
	sameSite?: 'strict' | 'lax' | 'none';
	partitioned?: boolean;
}
interface CookieStore {
	set(init: CookieInit): Promise<void>;
}
