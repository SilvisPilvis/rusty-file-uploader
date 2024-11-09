// @ts-check
import { defineConfig } from 'astro/config';

import tailwind from '@astrojs/tailwind';

import svelte from '@astrojs/svelte';

// https://astro.build/config
export default defineConfig({
  integrations: [tailwind(), svelte()],
  security: {
    checkOrigin: true,
  },
  server: {
    host: '0.0.0.0',
    port: 4321
  },
  vite: {
    server: {
      // hmr: {
      //   host: '127.0.0.1',
      //   clientPort: 4321,
      // },
      watch: {
        usePolling: true,
      },
    },
  },
  output: "server",
});