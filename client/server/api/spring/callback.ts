import { getQuery, sendRedirect, setCookie } from "h3"

export default async (req: any, res: any) => {
    const { code } = getQuery(req)

    if (!code) {
        return sendRedirect(res, "/")
    }

    const response: any = await $fetch(
        `${process.env.AUTHORIZATION_SERVER_URL}/oauth2/token`,
        {
            method: "POST",
            body: {
                client_id: process.env.CLIENT_ID,
                client_secret: process.env.CLIENT_SECRET,
                code,
            },
        }
    )

    if (response.error) {
        return sendRedirect(res, "/")
    }

    setCookie(res, "spring_token", response.access_token, { path: "/" })

    return sendRedirect(res, "/")
}