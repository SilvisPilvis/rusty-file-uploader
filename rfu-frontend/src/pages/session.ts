export async function get(context: any) {
    //return { body: "Session" };
    Astro.cookies.delete("token");
    return Astro.redirect("/login");
}
