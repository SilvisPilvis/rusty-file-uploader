/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
	theme: {
		extend: {
			colors: {
				'text': '#f3edf3',
				'background': '#080408',
				// 'primary': '#9f1239',
				'primary': '#4c0519',
				'secondary': '#7d2e49',
				// 'accent': '#c1608b',
				'accent': '#b1a870',
			},
		},
	},
	plugins: [],
}

