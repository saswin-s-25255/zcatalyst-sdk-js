import {
	clearOAuthTokenFromIDB,
	clearStratusJwt,
	ConfigStore,
	getCredentials,
	getOAuthTokenFromIDB,
	JWT_COOKIE_PREFIX,
	setDefaultProjectConfig,
	setOAuthTokenInIDB
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
import { isIframeContext as detectIframeContext } from './utils/browser';
import {
	AUTH_ERROR_MSG,
	AUTH_STATIC_FILES,
	CURRENT_CLIENT_PAGE_HOST,
	CURRENT_CLIENT_PAGE_PORT,
	CURRENT_CLIENT_PAGE_PROTOCOL,
	FETCH_DETAILS_CALLBACK_FN,
	POPUP_DEFAULT_HEIGHT,
	POPUP_DEFAULT_IS_HOSTED,
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
	ICatalystCustomTokenResponse,
	ICatalystDeliverAuthTokenConfig,
	ICatalystDeliverSignOutDoneConfig,
	ICatalystPopupSignInConfig,
	ICatalystPopupSignInResult,
	ICatalystSignInConfig,
	ICatalystSignUpConfig,
	IPopupAuthOperation,
	UserDetails
} from './utils/interface';
import {
	buildPopupLoginUrl,
	buildPopupLogoutUrl,
	createPopupEventId,
	deliverAuthTokenToParent as postAuthTokenToParent,
	deliverSignOutDoneToParent as postSignOutDoneToParent,
	openPopupWindow
} from './utils/popup-auth';
import { applyQueryString, hasSuffInfo } from './utils/validators';

type Token_responce = {
	expires_in_sec: number;
	access_token: string;
};

const { CREDENTIAL_USER, REQ_METHOD, COMPONENT } = CONSTANTS;

/** Popup message-type / path constants exposed on {@link zcAuth}. */
export const popupConstants = {
	POPUP_LOGIN_PATH,
	POPUP_LOGOUT_PATH,
	POPUP_MSG_AUTH_REQUEST,
	POPUP_MSG_AUTH_TOKEN,
	POPUP_MSG_SIGNOUT_DONE,
	POPUP_MSG_AUTH_ERROR
} as const;

/** Provides browser authentication flows for hosted sign-in, embedded sign-in, sign-up, and user profile access. */
class Authentication implements Component {
	requester: Handler;
	zaid: string = ConfigStore.get('ZAID') as string;
	projectId: string = ConfigStore.get('PROJECT_ID') as string;
	isAppsail: string = ConfigStore.get('IS_APPSAIL') as string;
	authProtocol: Auth_Protocol = ConfigStore.get('AUTH_PROTOCOL') as unknown as Auth_Protocol;
	readonly popupConstants = popupConstants;
	#popupAuthOperation: IPopupAuthOperation | null = null;
	#popupPollInterval: ReturnType<typeof setInterval> | null = null;
	#popupTimeoutHandle: ReturnType<typeof setTimeout> | null = null;
	#popupMessageListener: ((event: MessageEvent) => void) | null = null;
	#tokenRefreshTimer: ReturnType<typeof setTimeout> | null = null;
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
	async init(): Promise<void> {
		// Ensure credentials (project_id, zaid, org_id, etc.) are fetched before
		// any auth operation. The constructor fires getCredentials() in the background
		// (fire-and-forget), so awaiting it here guarantees project_id is set before
		// isUserAuthenticated() / signIn() / generateAuthToken() run — preventing
		// URLs like /baas/v1/project/undefined/project-user/current in popup contexts.
		await getCredentials();
		// Refresh instance fields from ConfigStore after getCredentials() completes.
		// The constructor reads ConfigStore before credentials are fetched, so fields
		// like this.zaid and this.projectId are undefined at construction time in popup
		// contexts where the fire-and-forget getCredentials() hasn't finished yet.
		// Re-reading here ensures generateAuthToken() and other methods use the correct values.
		this.zaid = ConfigStore.get('ZAID') as string;
		this.projectId = ConfigStore.get('PROJECT_ID') as string;
		this.isAppsail = ConfigStore.get('IS_APPSAIL') as string;
		this.authProtocol = ConfigStore.get('AUTH_PROTOCOL') as unknown as Auth_Protocol;
		//Only inside the iframe getOAuthTokenFromIDB will return a data.
		const storedToken = await getOAuthTokenFromIDB().catch(() => null);
		if (storedToken && storedToken.exp > Date.now()) {
			this.#setAuthProtocol(Auth_Protocol.OAuthTokenProtocol);
			// Rehydrate the proactive refresh timer after a page reload.
			// The timer is lost on every reload, so we recreate it here from
			// the absolute expiry timestamp persisted in IndexedDB.
			// Guard: if a timer is already running (e.g. init() called twice),
			// do not overwrite it.
			if (this.#tokenRefreshTimer === null) {
				this.#scheduleTokenRefresh(storedToken.exp);
			}
		}
	}

	/**
	 * Returns whether the SDK is running inside an iframe.
	 *
	 * @example
	 * ```ts
	 * if (zcAuth.isIframeContext()) {
	 *   await zcAuth.signInViaPopup();
	 * }
	 * ```
	 */
	isIframeContext(): boolean {
		return detectIframeContext();
	}

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
		// Ensure credentials are loaded before using projectId/zaid.
		// If init() was not called, or if the constructor's fire-and-forget
		// getCredentials() hasn't finished yet, this guarantees they are ready.
		if (!ConfigStore.get('INITIALIZED')) {
			await getCredentials();
			this.zaid = ConfigStore.get('ZAID') as string;
			this.projectId = ConfigStore.get('PROJECT_ID') as string;
			this.isAppsail = ConfigStore.get('IS_APPSAIL') as string;
			this.authProtocol = ConfigStore.get('AUTH_PROTOCOL') as unknown as Auth_Protocol;
		}

		// Default redirect target: use caller-provided URL or fall back to the
		// current path so the user lands back where they were after sign-in.
		const redirectTarget =
			config.redirectUrl ??
			config.serviceUrl ??
			window.location.pathname + window.location.search;

		if (detectIframeContext()) {
			await this.signInViaPopup({
				width: config.popupWidth,
				height: config.popupHeight,
				timeoutMs: config.popupTimeoutMs,
				isHosted: config.isHosted
			});
			// After popup auth completes, redirect to the intended path.
			window.location.href = redirectTarget;
			return;
		}
		try {
			const isValidUser = await this.#isValidUser();
			if (isValidUser) {
				window.location.href = this.#constructRedirectUrl(redirectTarget);
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
		this.#setAuthProtocol(Auth_Protocol.JwtTokenProtocol);
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
		const authProtocol = ConfigStore.get('AUTH_PROTOCOL') as unknown as Auth_Protocol;
		this.authProtocol = authProtocol;
		if (detectIframeContext()) {
			await this.signOutViaPopup(redirectURL);
			return;
		}
		// Fix 1 & 2 & 3: JWT — clear its own cookies with past expiry, reset config, redirect
		if (authProtocol === Auth_Protocol.JwtTokenProtocol) {
			document.cookie = `${JWT_COOKIE_PREFIX}=; path=/; expires=${new Date(0).toUTCString()};`;
			document.cookie = `user_cred=; path=/; expires=${new Date(0).toUTCString()};`;
			clearStratusJwt();
			setDefaultProjectConfig();
			window.location.replace(redirectURL);
			return;
		}
		// Fix 1 & 3: OAuth — only clear IDB token (no user_cred, no stratus_jwt), reset config, redirect
		if (authProtocol === Auth_Protocol.OAuthTokenProtocol) {
			await this.#clearTokenStorage();
			setDefaultProjectConfig();
			window.location.replace(redirectURL);
			return;
		}
		// ZcrfTokenProtocol — clear stratus_jwt, reset config, then hit Accounts logout
		// Fix 3 & 4 & 5: clear stratus_jwt, reset config before Accounts redirect
		clearStratusJwt();
		setDefaultProjectConfig();
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
				// The Accounts logout endpoint invalidates the CAUTH session cookie
				// server-side — no client-side cookie deletion needed or possible
				// (the server may set it HttpOnly, which blocks JS access).
				await this.requester.send(request);
				window.location.replace(redirectURL);
			} catch {
				window.location.replace(this.#constructSignOutUrl(redirectURL));
			}
		} else {
			window.location.replace(this.#constructSignOutUrl(redirectURL));
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
			method: REQ_METHOD.post,
			path: changePasswordUrl,
			type: RequestType.JSON,
			data: {
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

	#setAuthProtocol(protocol: Auth_Protocol): void {
		this.authProtocol = protocol;
		ConfigStore.set('AUTH_PROTOCOL', protocol);
	}

	// Schedules a proactive token refresh from an absolute expiry timestamp.
	// Works for both fresh tokens (#setTokenStorage) and rehydrated tokens
	// recovered from IndexedDB after a page reload (init()).
	// Uses Math.max(0, ...) so tokens with fewer than 5 minutes remaining
	// are refreshed immediately on the next event-loop tick.
	#scheduleTokenRefresh(expiresAt: number): void {
		const FIVE_MINUTES_MS = 5 * 60 * 1000; //5 min
		const refreshInMs = Math.max(0, expiresAt - Date.now() - FIVE_MINUTES_MS);
		this.#tokenRefreshTimer = setTimeout(() => {
			this.generateAuthToken('functions')
				.then((token) => this.#setTokenStorage(token.access_token, token.expires_in_sec))
				.catch(() => {
					// Refresh failed — token will be invalid when it expires;
					// the next call requiring auth will re-trigger the popup flow.
				});
		}, refreshInMs);
	}

	async #setTokenStorage(accessToken: string, expiresInSec: number): Promise<number> {
		const expiresAt = Date.now() + expiresInSec * 1000;
		await setOAuthTokenInIDB(accessToken, expiresAt);
		// Clear any existing timer so only one refresh is ever pending,
		// then schedule the next proactive refresh via the shared helper.
		if (this.#tokenRefreshTimer !== null) {
			clearTimeout(this.#tokenRefreshTimer);
			this.#tokenRefreshTimer = null;
		}
		this.#scheduleTokenRefresh(expiresAt);
		return expiresAt;
	}

	async #clearTokenStorage(): Promise<void> {
		if (this.#tokenRefreshTimer !== null) {
			clearTimeout(this.#tokenRefreshTimer);
			this.#tokenRefreshTimer = null;
		}
		await clearOAuthTokenFromIDB();
	}

	#clearPopupOperation(status: IPopupAuthOperation['status'] = 'cancelled'): void {
		if (this.#popupAuthOperation) {
			this.#popupAuthOperation.status = status;
			try {
				if (this.#popupAuthOperation.popup && !this.#popupAuthOperation.popup.closed) {
					this.#popupAuthOperation.popup.close();
				}
			} catch {
				// ignore cross-origin close errors
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
		const isHosted = config.isHosted ?? POPUP_DEFAULT_IS_HOSTED;
		const eventId = createPopupEventId();

		return new Promise<ICatalystPopupSignInResult>((resolve, reject) => {
			const onMessage = async (event: MessageEvent): Promise<void> => {
				if (!this.#popupAuthOperation || this.#popupAuthOperation.status !== 'waiting') {
					return;
				}
				if (event.origin !== window.location.origin || !event.data) {
					return;
				}
				// Verify the message genuinely came from our popup window.
				// Origin alone is not enough — any same-origin frame could
				// send a forged POPUP_MSG_AUTH_ERROR and cancel the sign-in
				// before the eventId check is reached.
				if (event.source !== this.#popupAuthOperation.popup) {
					return;
				}
				// Verify the eventId before acting on any message type,
				// so no message type can bypass this correlation check.
				if (event.data.eventId !== this.#popupAuthOperation.eventId) {
					return;
				}
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
				if (event.data.type !== POPUP_MSG_AUTH_TOKEN) {
					return;
				}

				const accessToken = event.data.access_token;
				if (typeof accessToken !== 'string' || !accessToken || accessToken.length > 1000) {
					this.#clearPopupOperation('cancelled');
					reject(
						new CatalystAuthenticationError(
							'INVALID_TOKEN',
							'Popup sent missing or malformed token.'
						)
					);
					return;
				}

				try {
					const expiresInSec =
						typeof event.data.expires_in_sec === 'number' &&
						isFinite(event.data.expires_in_sec) &&
						event.data.expires_in_sec > 0 &&
						event.data.expires_in_sec < 86400 * 30
							? event.data.expires_in_sec
							: 3600;
					this.#popupAuthOperation.status = 'completed';
					const expiresAt = await this.#setTokenStorage(accessToken, expiresInSec);
					this.#setAuthProtocol(Auth_Protocol.OAuthTokenProtocol);
					this.#clearPopupOperation('completed');
					resolve({
						access_token: accessToken,
						expires_at: expiresAt,
						event_id: eventId
					});
				} catch (err) {
					this.#clearPopupOperation('cancelled');
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

			let popup: Window;
			try {
				popup = openPopupWindow({
					url: buildPopupLoginUrl(window.location.origin, eventId, isHosted),
					name: 'catalystSignIn',
					width,
					height
				});
			} catch (err) {
				// Popup was blocked or failed to open — clean up the listener
				// before rejecting so it is not left installed indefinitely.
				window.removeEventListener('message', onMessage);
				this.#popupMessageListener = null;
				reject(
					new CatalystAuthenticationError(
						'POPUP_BLOCKED',
						err instanceof Error ? err.message : 'Popup window could not be opened.'
					)
				);
				return;
			}
			this.#popupAuthOperation = { eventId, status: 'waiting', popup, createdAt: Date.now() };

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
					// suppress during cross-origin redirects
				}
			}, POPUP_POLL_INTERVAL_MS);

			this.#popupTimeoutHandle = setTimeout(() => {
				if (this.#popupAuthOperation?.status === 'waiting') {
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

	async signOutViaPopup(redirectUrl = '/'): Promise<void> {
		const popup = openPopupWindow({
			url: buildPopupLogoutUrl(window.location.origin),
			name: 'catalystSignOut',
			width: POPUP_DEFAULT_WIDTH,
			height: POPUP_DEFAULT_HEIGHT
		});
		return new Promise<void>((resolve, reject) => {
			const timeoutHandle = setTimeout(() => {
				window.removeEventListener('message', onMessage);
				try {
					if (!popup.closed) {
						popup.close();
					}
				} catch {
					// ignore close errors
				}
				reject(new CatalystAuthenticationError('POPUP_TIMEOUT', 'Sign-out timed out.'));
			}, POPUP_DEFAULT_TIMEOUT_MS);

			const onMessage = async (event: MessageEvent): Promise<void> => {
				if (event.origin !== window.location.origin || !event.data) {
					return;
				}
				// Verify the message came from our sign-out popup, not another
				// same-origin frame that could forge a POPUP_MSG_SIGNOUT_DONE.
				if (event.source !== popup) {
					return;
				}
				if (event.data.type !== POPUP_MSG_SIGNOUT_DONE) {
					return;
				}
				clearTimeout(timeoutHandle);
				window.removeEventListener('message', onMessage);
				try {
					if (!popup.closed) {
						popup.close();
					}
				} catch {
					// ignore close errors
				}
				await this.#clearTokenStorage();
				if (redirectUrl) {
					window.location.replace(redirectUrl);
				}
				resolve();
			};

			window.addEventListener('message', onMessage);
		});
	}

	/**
	 * Sends the OAuth access token from the popup window to the opener via postMessage.
	 * Intended for the popup login page at `/__catalyst/auth/login/popup/{eventId}`.
	 *
	 * When `access_token` and `expires_in_sec` are omitted, they are fetched via
	 * {@link generateAuthToken}. `eventId` is resolved from the popup URL when omitted.
	 *
	 * @param config - Token delivery configuration.
	 * @returns A promise that resolves after the token is posted to the parent window.
	 *
	 * @example
	 * ```ts
	 * await zcAuth.init();
	 * await zcAuth.deliverAuthTokenToParent({ targetOrigin: window.location.origin });
	 * ```
	 */
	async deliverAuthTokenToParent(config: ICatalystDeliverAuthTokenConfig = {}): Promise<void> {
		let accessToken = config.access_token;
		let expiresInSec = config.expires_in_sec;

		if (!accessToken || !expiresInSec) {
			const token = await this.generateAuthToken(config.feature ?? 'functions');
			accessToken = accessToken ?? token.access_token;
			expiresInSec = expiresInSec ?? token.expires_in_sec;
		}

		postAuthTokenToParent({
			access_token: accessToken,
			expires_in_sec: expiresInSec,
			eventId: config.eventId,
			targetOrigin: config.targetOrigin
		});
	}

	/**
	 * Notifies the opener that popup sign-out completed.
	 * Intended for the popup logout page at `/__catalyst/auth/logout/popup`.
	 *
	 * @param config - Optional target origin for postMessage.
	 *
	 * @example
	 * ```ts
	 * zcAuth.deliverSignOutDoneToParent({ targetOrigin: window.location.origin });
	 * ```
	 */
	deliverSignOutDoneToParent(config: ICatalystDeliverSignOutDoneConfig = {}): void {
		postSignOutDoneToParent(config.targetOrigin);
	}

	async generateAuthToken(feature: 'functions' | 'stratus'): Promise<Token_responce> {
		const customTokenRequest: IRequestConfig = {
			method: REQ_METHOD.get,
			path: '/authentication/custom-token',
			type: RequestType.JSON,
			service: CatalystService.BAAS,
			user: CREDENTIAL_USER.user,
			qs: {
				feature
			}
		};
		const customTokenResp = await this.requester.send(customTokenRequest);
		const customTokenData = customTokenResp.data.data as ICatalystCustomTokenResponse;

		const remoteAuthRequest: IRequestConfig = {
			method: REQ_METHOD.post,
			service: CatalystService.EXTERNAL,
			path: `/clientoauth/v2/${this.zaid}/remote/auth`,
			origin: ConfigStore.get('IAM_DOMAIN') as string,
			auth: false,
			headers: {
				Origin: window.location.origin
			},
			qs: {
				response_type: 'remote_token',
				scope: customTokenData.scopes.join(' '),
				client_id: customTokenData.client_id,
				jwt_token: customTokenData.jwt_token
			}
		};

		const remoteAuthResp = await this.requester.send(remoteAuthRequest);
		const remoteAuthData = remoteAuthResp.data as {
			access_token?: string;
			access_toke?: string;
			expires_in_sec?: number;
			expires_in?: number;
		};

		const accessToken = remoteAuthData.access_token ?? remoteAuthData.access_toke;
		if (!accessToken) {
			throw new CatalystAuthenticationError(
				'AUTHENTICATION_ERROR',
				'Unable to exchange JWT token for an OAuth access token.'
			);
		}

		const expiresInSec =
			typeof remoteAuthData.expires_in_sec === 'number'
				? remoteAuthData.expires_in_sec
				: typeof remoteAuthData.expires_in === 'number'
					? remoteAuthData.expires_in
					: 3600;
		return {
			access_token: accessToken,
			expires_in_sec: expiresInSec
		};
	}
}
export { UserManagement } from './user-management';
export { isIframeContext } from './utils/browser';
export * from './utils/constants';

export const zcAuth = new Authentication();

declare global {
	interface Window {
		I18N?: {
			data?: Record<string, unknown>;
		};
	}
}
