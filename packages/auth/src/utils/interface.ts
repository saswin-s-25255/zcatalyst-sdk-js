import { ICatalystJSON } from '@zcatalyst/utils';

export interface ICatalystSysUser {
	user_id: string;
	email_id: string;
	first_name: string;
	last_name: string;
	zuid?: string;
	is_confirmed?: boolean;
}

export interface ICatalystUser {
	zuid: string;
	/** @deprecated use {@link org_id} field instead */
	zaaid?: string;
	org_id: string;
	status: string;
	user_id: string;
	is_confirmed: boolean;
	email_id: string;
	first_name: string;
	last_name: string;
	created_time: string;
	modified_time: string;
	invited_time: string;
	role_details: {
		role_id: string;
		role_name: string;
	};
}

export interface ICatalystSignupConfig extends ICatalystJSON {
	platform_type: string;
	redirect_url?: string;
	template_details?: {
		senders_mail?: string;
		subject?: string;
		message?: string;
	};
}

export interface ICatalystSignupUserConfig extends ICatalystJSON {
	first_name: string;
	last_name?: string;
	email_id: string;
	org_id: string;
}

export interface ICatalystSignupValidationReq {
	user_details: {
		email_id: string;
		first_name: string;
		last_name: string;
		org_id?: string;
		role_details?: {
			role_id: string;
			role_name: string;
		};
	};
	auth_type: 'web' | 'mobile';
}

export interface ICatalystCustomTokenDetails extends ICatalystJSON {
	type: 'web' | 'mobile';
	user_details: {
		email_id: string;
		first_name: string;
		last_name: string;
		org_id?: string;
		role_name?: string;
		phone_number?: string;
		country_code?: string;
	};
}

export interface ICatalystCustomTokenResponse {
	jwt_token: string;
	client_id: string;
	scopes: Array<string>;
}

export interface ICatalystSignInConfig {
	signInProvidersOnly?: boolean;
	cssUrl?: string;
	is_customize_forgot_password?: boolean;
	forgotPasswordId?: string;
	forgotPasswordCssUrl?: string;
	serviceUrl?: string;
	redirectUrl?: string;
	/** Popup window width in pixels when signIn() is called inside an iframe. */
	popupWidth?: number;
	/** Popup window height in pixels when signIn() is called inside an iframe. */
	popupHeight?: number;
	/** Popup timeout in ms when signIn() is called inside an iframe. */
	popupTimeoutMs?: number;
}

// ── Popup Auth Interfaces ──────────────────────────────────────────────────

/**
 * Options for signInViaPopup().
 */
export interface ICatalystPopupSignInConfig {
	/** Width of the popup window in pixels. Defaults to 500. */
	width?: number;
	/** Height of the popup window in pixels. Defaults to 650. */
	height?: number;
	/** Timeout in milliseconds to wait for the popup to respond. Defaults to 300000 (5 min). */
	timeoutMs?: number;
}

/**
 * Result returned by signInViaPopup() after a successful sign-in.
 */
export interface ICatalystPopupSignInResult {
	/** The authenticated user details. */
	user: unknown;
	/** The tokens written as cookies — functions JWT and stratus JWT. */
	tokens: {
		functions: string; // → JWT_AUTH_TOKEN cookie
		stratus: string; // → stratus_jwt cookie (JWT_STRATUS_AUTH in old SDK)
	};
}

/**
 * Internal state object tracking a single popup auth operation.
 * Mirrors Firebase's PopupOperation pattern.
 */
export interface IPopupAuthOperation {
	/** Unique transaction ID generated per login attempt (like Firebase's eventId). */
	eventId: string;
	/** Status of the current operation. */
	status: 'waiting' | 'completed' | 'cancelled' | 'expired';
	/** Reference to the opened popup window. */
	popup: Window | null;
	/** Timestamp when the operation was created. */
	createdAt: number;
}

export interface ICatalystAuthResponse {
	status: number;
	message?: string;
	data: Record<string, unknown>;
}

export interface UserDetails {
	name?: string;
	first_name?: string;
	last_name?: string;
	email_id?: string;
}

export interface BodyData {
	[key: string]: unknown; // allows any string as a key
}

export interface ICatalystAppConfig {
	projectId: string;
	projectKey?: string;
	projectDomain?: string;
	environment: string;
	projectSecretKey?: string;
}

export interface ICatalystCredentials {
	refresh_token?: string;
	client_id?: string;
	client_secret?: string;
	access_token?: string;
	ticket?: string;
}

export interface ICatalystSignUpConfig {
	first_name: string;
	redirect_url?: string;
	platform_type?: string;
	last_name: string;
	email_id: string;
}
