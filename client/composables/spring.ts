export const useSpringCookie = () => useCookie("spring_token")

export const springFetch = (url: string, fetchOptions: any = {}) => {
    const { AUTHORIZATION_SERVER_URL } = useRuntimeConfig()

    return $fetch(url, {
        baseURL: `${AUTHORIZATION_SERVER_URL}`,
        ...fetchOptions,
        headers: {
            Authorization: `Bearer ${useSpringCookie().value}`,
            ...fetchOptions.headers
        }
    })
}

export const springUser = async () => {
    const cookie = useSpringCookie()
    const user = useState("spring_user")
    if (cookie.value && !user.value) {
        user.value = await springFetch("/user")
    }
    return user;
}

export const springLogin = () => {
    if (process.client) {
        const { AUTHORIZATION_SERVER_URL, CLIENT_ID } = useRuntimeConfig()
        console.log(AUTHORIZATION_SERVER_URL)
        window.location.replace(`${AUTHORIZATION_SERVER_URL}/oauth2/authorize?client_id=${CLIENT_ID}&scope=openid`)
    }
}

export const springLogout = async () => {
    useSpringCookie().value = null
    useState("spring_user").value = null
}