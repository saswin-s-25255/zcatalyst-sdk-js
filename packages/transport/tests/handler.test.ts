import { Auth_Protocol, ConfigStore } from '@zcatalyst/auth-client';

import { Handler } from '../src';
import { ResponseHandler } from '../src/fetch-handler';
import { RequestType, ResponseType } from '../src/utils/enums';
import { IRequestConfig } from '../src/utils/interfaces';

describe('Handler', () => {
	const idbStore = new Map();
	const sessionStore = new Map<string, string>();

	function setupSessionStorageMock() {
		const sessionStorageMock = {
			getItem: (key: string) => (sessionStore.has(key) ? sessionStore.get(key)! : null),
			setItem: (key: string, value: string) => {
				sessionStore.set(key, value);
			},
			removeItem: (key: string) => {
				sessionStore.delete(key);
			},
			clear: () => {
				sessionStore.clear();
			},
			key: (index: number) => Array.from(sessionStore.keys())[index] ?? null,
			get length() {
				return sessionStore.size;
			}
		};

		(globalThis as any).sessionStorage = sessionStorageMock;
	}

	function setupIndexedDBMock() {
		(global as unknown as { indexedDB: unknown }).indexedDB = {
			open: jest.fn(() => {
				const request: any = {
					result: {
						objectStoreNames: {
							contains: () => true
						},
						createObjectStore: jest.fn(),
						transaction: () => {
							const transaction: any = {};
							const store = {
								get: (key: string) => {
									const idbRequest: any = {};
									queueMicrotask(() => {
										idbRequest.result = idbStore.get(key);
										idbRequest.onsuccess?.(new Event('success'));
										transaction.oncomplete?.(new Event('complete'));
									});
									return idbRequest;
								},
								put: (value: unknown, key: string) => {
									const idbRequest: any = {};
									queueMicrotask(() => {
										idbStore.set(key, value);
										idbRequest.result = undefined;
										idbRequest.onsuccess?.(new Event('success'));
										transaction.oncomplete?.(new Event('complete'));
									});
									return idbRequest;
								},
								delete: (key: string) => {
									const idbRequest: any = {};
									queueMicrotask(() => {
										idbStore.delete(key);
										idbRequest.result = undefined;
										idbRequest.onsuccess?.(new Event('success'));
										transaction.oncomplete?.(new Event('complete'));
									});
									return idbRequest;
								}
							};
							return {
								objectStore: () => store,
								set oncomplete(handler: unknown) {
									transaction.oncomplete = handler;
								},
								get oncomplete() {
									return transaction.oncomplete;
								},
								set onerror(handler: unknown) {
									transaction.onerror = handler;
								},
								get onerror() {
									return transaction.onerror;
								},
								error: null
							};
						},
						close: jest.fn()
					}
				};
				queueMicrotask(() => {
					request.onsuccess?.(new Event('success'));
				});
				return request;
			})
		};
	}

	beforeEach(() => {
		setupSessionStorageMock();
		ConfigStore.clear();
		sessionStore.clear();
		idbStore.clear();
		setupIndexedDBMock();
	});

	describe('request configuration', () => {
		it('should handle JSON request type', () => {
			const config: IRequestConfig = {
				method: 'POST',
				path: '/test',
				type: RequestType.JSON,
				data: { key: 'value' }
			};

			expect(config.type).toBe(RequestType.JSON);
			expect(config.data).toEqual({ key: 'value' });
		});

		it('should handle FILE request type', () => {
			const config: IRequestConfig = {
				method: 'POST',
				path: '/upload',
				type: RequestType.FILE,
				data: { file: 'test' }
			};

			expect(config.type).toBe(RequestType.FILE);
		});

		it('should handle query parameters', () => {
			const config: IRequestConfig = {
				method: 'GET',
				path: '/test',
				qs: { param1: 'value1', param2: 'value2' }
			};

			expect(config.qs).toEqual({ param1: 'value1', param2: 'value2' });
		});
	});

	describe('response types', () => {
		it('should handle JSON response type', () => {
			const config: IRequestConfig = {
				method: 'GET',
				path: '/test',
				expecting: ResponseType.JSON
			};

			expect(config.expecting).toBe(ResponseType.JSON);
		});

		it('should handle STRING response type', () => {
			const config: IRequestConfig = {
				method: 'GET',
				path: '/test',
				expecting: ResponseType.STRING
			};

			expect(config.expecting).toBe(ResponseType.STRING);
		});

		it('should handle BUFFER response type', () => {
			const config: IRequestConfig = {
				method: 'GET',
				path: '/test',
				expecting: ResponseType.BUFFER
			};

			expect(config.expecting).toBe(ResponseType.BUFFER);
		});

		it('should handle RAW response type', () => {
			const config: IRequestConfig = {
				method: 'GET',
				path: '/test',
				expecting: ResponseType.RAW
			};

			expect(config.expecting).toBe(ResponseType.RAW);
		});
	});

	describe('OAuth auth headers', () => {
		it('should attach Zoho OAuth token from IndexedDB', async () => {
			ConfigStore.set('AUTH_PROTOCOL', Auth_Protocol.OAuthTokenProtocol);
			idbStore.set('zcatalyst_client_token', {
				token: 'oauth-token',
				exp: Date.now() + 60_000
			});

			const headers = (await ResponseHandler.attachZCAuthHeaders({})) as Record<
				string,
				string
			>;

			expect(headers.Authorization).toBe('Zoho-oauthtoken oauth-token');
		});

		it('should return headers unchanged when auth protocol is not set', async () => {
			ConfigStore.clear();
			const headers = (await ResponseHandler.attachZCAuthHeaders({
				Accept: 'application/json'
			})) as Record<string, string>;

			expect(headers.Accept).toBe('application/json');
			expect(headers.Authorization).toBeUndefined();
		});

		it('should reject when OAuth token is missing', async () => {
			await expect(ResponseHandler.getOAuthZCAuthToken()).rejects.toThrow(
				'No access token found.'
			);
		});

		it('should reject when OAuth token is expired', async () => {
			idbStore.set('zcatalyst_client_token', {
				token: 'oauth-token',
				exp: Date.now() - 1000
			});

			await expect(ResponseHandler.getOAuthZCAuthToken()).rejects.toThrow(
				'Access token has expired.'
			);
			expect(idbStore.has('zcatalyst_client_token')).toBe(false);
		});

		it('should attach Bearer token for legacy JWT protocol', async () => {
			(globalThis as any).document = {
				cookie: 'JWT_AUTH=jwt-token'
			};
			ConfigStore.set('AUTH_PROTOCOL', Auth_Protocol.JwtTokenProtocol);
			ConfigStore.set('JWT_AUTH', 'Bearer');

			const headers = (await ResponseHandler.attachZCAuthHeaders({})) as Record<
				string,
				string
			>;

			expect(headers.Authorization).toBe('Bearer jwt-token');
		});
	});

	describe('appendQueryString', () => {
		it('should preserve existing params when appending query strings', () => {
			const result = ResponseHandler.appendQueryString('/path?existing=1', {
				added: '2'
			});

			expect(result).toBe('/path?existing=1&added=2');
		});

		it('should return url unchanged when no query params are provided', () => {
			expect(ResponseHandler.appendQueryString('/path')).toBe('/path');
		});
	});

	describe('wrapResponse', () => {
		it('should avoid parsing body for no-content responses', async () => {
			const response = {
				status: 204,
				headers: {},
				json: jest.fn(),
				text: jest.fn(),
				blob: jest.fn(),
				arrayBuffer: jest.fn()
			} as unknown as Response;

			const wrapped = await ResponseHandler.wrapResponse(response, {
				request: { method: 'GET' }
			});

			expect(wrapped.data).toBe('');
		});
	});
});
