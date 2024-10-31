// Common cookie expiration times
export const expirations = {
    oneMinute: 60,
    oneHour: 60 * 60,
    oneDay: 60 * 60 * 24,
    oneWeek: 60 * 60 * 24 * 7,
    oneMonth: 60 * 60 * 24 * 30,
    oneYear: 60 * 60 * 24 * 365
};

import type { APIContext } from "astro";

// ...

// export function setSessionTokenCookie(context: APIContext, token: string, expiresAt: Date): void {
// 	context.cookies.set("session", token, {
// 		httpOnly: true,
// 		sameSite: "lax",
// 		secure: import.meta.env.PROD,
// 		expires: expiresAt,
// 		path: "/"
// 	});
// }

export function setSessionTokenCookie(context: APIContext, token: string, expiresAt: Date): void {
	context.cookies.set("session", token, {
		httpOnly: true,
		sameSite: "lax",
		secure: import.meta.env.PROD,
		expires: expiresAt,
		path: "/"
	});
}

export function deleteSessionTokenCookie(context: APIContext): void {
	context.cookies.set("session", "", {
		httpOnly: true,
		sameSite: "lax",
		// secure: import.meta.env.PROD,
    secure: true,
		maxAge: expirations.oneDay,
		path: "/"
	});
}



export function setCookie(name: string, value: string, options: {
    path?: string;
    httpOnly?: boolean;
    expires?: Date | number;
    maxAge?: number;
    domain?: string;
    secure?: boolean;
    sameSite?: 'Strict' | 'Lax' | 'None';
  } = {}) {
    // Basic cookie string
    let cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
  
    // Add options
    if (options.path) {
      cookie += `; Path=${options.path}`;
    }

    if (options.httpOnly) {
        cookie += `; HttpOnly;`;
    }
    
    // if (options.expires) {
    //   if (typeof options.expires === 'number') {
    //     // options.expires = new Date(Date.now() + options.expires * 1000);
    //     options.expires = expirations.oneDay;
    //   }
    //   cookie += `; Expires=${options.expires.toUTCString()}`;
    // }

    if (options.expires) {
        if (typeof options.expires === 'number') {
          options.expires = new Date(Date.now() + options.expires * 1000);
          cookie += `; Expires=${options.expires.toUTCString()}`;
        }else {
            options.expires = expirations.oneDay;
        }
      }
  
    if (options.maxAge) {
      cookie += `; Max-Age=${options.maxAge}`;
    }
  
    if (options.domain) {
      cookie += `; Domain=${options.domain}`;
    }
  
    if (options.secure) {
      cookie += '; Secure';
    }
  
    if (options.sameSite) {
      cookie += `; SameSite=${options.sameSite}`;
    }
  
    return cookie;
}