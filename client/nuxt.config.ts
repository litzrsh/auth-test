// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
    runtimeConfig: {
        public: {
            AUTHORIZATION_SERVER_URL: process.env.AUTHORIZATION_SERVER_URL || "http://localhost:9000",
            CLIENT_ID: process.env.CLIENT_ID
        }
    }
})
