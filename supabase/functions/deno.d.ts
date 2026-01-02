// Global type definitions for Supabase Deno functions

// Extend existing Deno namespace instead of redeclaring
declare global {
  // Define the serve function from Deno's HTTP server
  function serve(
    handler: (request: Request) => Response | Promise<Response>,
    options?: { port?: number; hostname?: string }
  ): void;
}

// Declare modules for Deno imports
declare module "https://deno.land/std@0.177.0/http/server.ts" {
  export function serve(
    handler: (request: Request) => Response | Promise<Response>,
    options?: { port?: number; hostname?: string }
  ): void;
}

export {};