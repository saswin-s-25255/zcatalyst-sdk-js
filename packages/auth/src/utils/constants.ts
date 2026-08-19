export const UM_URL_DIVIDER = {
	PROJECT_USER: 'project-user',
	DISABLE: 'disable',
	ENABLE: 'enable',
	FORGOT_PASSWORD: 'forgotpassword',
	CURRENT: 'current'
};

export const URL_DIVIDER = {
	RESERVED_URL: '__catalyst',
	AUTH: 'auth',
	PUBLIC_SIGNUP: 'public-signup',
	CHANGE_PASSWORD: 'change-password',
	LOGIN: 'login',
	LOGIN_POPUP: 'login/popup',
	LOGOUT_POPUP: 'logout/popup'
};

// ── Popup Auth Constants ───────────────────────────────────────────────────

/**
 * Base path for the POC popup sign-in page served by the React SPA.
 * The eventId is appended at runtime: POPUP_LOGIN_PATH + '/' + eventId
 * e.g.  /__cat/auth/login/popup/3827491023
 *
 * NOTE: This intentionally differs from the broken backend route
 *       /__catalyst/auth/login/popup  — this POC replaces that behaviour.
 */
export const POPUP_LOGIN_PATH = `/__cat/auth/login/popup`;

/** Full path to the popup sign-out page served by the Catalyst backend. */
export const POPUP_LOGOUT_PATH = `/__cat/auth/logout/popup`;

/** postMessage type sent by iframe → popup to request the auth token. */
export const POPUP_MSG_AUTH_REQUEST = 'catalyst-auth-request';

/** postMessage type sent by popup → iframe carrying the JWT token. */
export const POPUP_MSG_AUTH_TOKEN = 'catalyst-auth-token';

/** postMessage type sent by popup → iframe when sign-out is complete. */
export const POPUP_MSG_SIGNOUT_DONE = 'catalyst-signout-done';

/** postMessage type sent by popup → iframe when an error occurs. */
export const POPUP_MSG_AUTH_ERROR = 'catalyst-auth-error';

/** Polling interval (ms) for iframe → popup keep-alive requests. */
export const POPUP_POLL_INTERVAL_MS = 500;

/** Default popup sign-in timeout (ms): 5 minutes. */
export const POPUP_DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

/** Default popup window width in pixels. */
export const POPUP_DEFAULT_WIDTH = 500;

/** Default popup window height in pixels. */
export const POPUP_DEFAULT_HEIGHT = 650;

/** Cookie key for the functions JWT token (used by API calls). */
export const JWT_FUNCTIONS_COOKIE_KEY = 'JWT_AUTH_TOKEN';

/** Cookie key for the stratus JWT token (used by Stratus). */
export const JWT_STRATUS_COOKIE_KEY = 'JWT_STRATUS_AUTH';

export const UM_QUERY_STRING = {
	EMAIL_ID: 'emailId'
};

export const signUpProperty = {
	FIRST_NAME: 'first_name',
	LAST_NAME: 'last_name',
	EMAIL_ID: 'email_id',
	REDIRECT_URL: 'redirect_url',
	PLATFORM: 'platform_type',
	USER_DETAILS: 'user_details',
	ZAID: 'zaid'
};

export const AUTH_ERROR_MSG = {
	emptyEmailAddress: 'Please enter your email address',
	noAccountIncludes: 'account does not exist',
	noAccountMsg: 'This account does not exist'
};

export type StrKeyStrValueType = {
	[property: string]: string;
};

export const AUTH_STATIC_FILES: StrKeyStrValueType = {
	URL: '/__catalyst/auth/static-file',
	SIGNIN: 'embedded_signin.css',
	SIGNIN_WITH_PROVIDERS_ONLY: 'embedded_signin_providers_only.css',
	FORGOT_PWD: 'embedded_password_reset.css'
};

export const REQUIREMENT = {
	INIT_REQUIRE: ['zaid', 'project_id']
};

export const APP_URL_DIVIDER = {
	PROJECT: 'project'
};

export const CSRF_TOKEN_KEY = 'ZD_CSRF_TOKEN';
export const COMMONPOOL_NAME = 'catalystApp';
export const PROJECT_ID = 'PROJECT_ID';
export const ZAID = 'ZAID';
export const IS_APPSAIL = 'IS_APPSAIL';
export const ACCOUNTS_PORTAL_DOMAIN = 'AUTH_DOMAIN';
export const API_DOMAIN = 'API_DOMAIN';
export const PROJECT = 'project';

// =============================================================================
// BROWSER ENVIRONMENT CONSTANTS
// =============================================================================

export const CURRENT_CLIENT_PAGE_HOST = document.location.hostname;
export const CURRENT_CLIENT_PAGE_PROTOCOL = document.location.protocol;
export const CURRENT_CLIENT_PAGE_PORT = document.location.port;
export const CURRENT_CLIENT_PAGE_ORIGIN = document.location.origin;
export const CURRENT_CLIENT_PAGE_HREF = document.location.href;

//
export const FETCH_DETAILS_CALLBACK_FN = 'FETCH_DETAILS_CALLBACK_FN';
