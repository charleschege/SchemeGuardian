use cookie::Cookie;
use std::borrow::Cow;

  #[allow(dead_code)]  
fn cookie_gen<N,V>(name: N, value: N) -> Cookie<'static> 
    where N: Into<Cow<'static, str>>,
          V: Into<Cow<'static, str>>
{
    Cookie::build(name, value)
        //.domain() !DONE [Create a way to limit a cookie to a certain domain based on `SchemeGuardian.toml` file]
        .path("/") /* !DONE [Create a way to limit the urls for cookies from SecretsEngine]*/
        .http_only(true)
        //.expires(format!("Expiry={}", Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()))
        .max_age(chrono::Duration::weeks(1))
        .finish()
}