#[macro_use]
extern crate lazy_static;
use futures::FutureExt;

#[macro_export]
macro_rules! some_or {
    ($e:expr, $b:block) => {
        if let Some(x) = $e {
            x
        } else {
            $b
        }
    };
}

#[macro_export]
macro_rules! ok_or {
    ($e:expr, $b:block) => {
        if let Ok(x) = $e {
            x
        } else {
            $b
        }
    };
}

lazy_static! {
    static ref ARGS: clap::ArgMatches<'static> = parse_args();
}

pub struct ServerState {
    username: String,
    password: String,
}

pub fn parse_auth(req: &hyper::Request<hyper::Body>) -> Option<(String, String)> {
    let line = some_or!(
        req.headers()
            .get("authorization")
            .and_then(|h| Some(h.as_bytes())),
        {
            return None;
        }
    );
    let u = ok_or!(String::from_utf8(line[6..].to_vec()), {
        return None;
    });
    let decoded = ok_or!(base64::decode(&u), {
        return None;
    });
    let s = ok_or!(String::from_utf8(decoded), {
        return None;
    });
    if let [username, password] = s.as_str().split(':').collect::<Vec<_>>().as_slice() {
        return Some((username.to_string(), password.to_string()));
    }
    return None;
}

fn auth_response(
    req: &hyper::Request<hyper::Body>,
    username: &str,
    password: &str,
) -> Option<hyper::Response<hyper::Body>> {
    let (rusername, rpassword) = match parse_auth(req) {
        Some(x) => x,
        None => {
            println!("no credentials in request");
            let builder = hyper::Response::builder()
                .header("WWW-Authenticate", "Basic realm=User Visible Realm")
                .status(hyper::StatusCode::UNAUTHORIZED);
            return Some(builder.body(hyper::Body::empty()).unwrap());
        }
    };

    if rusername != "admin" && (rusername != username || rpassword != password) {
        println!("ServerState: wrong user/pass");
        println!("user: {:?} - {:?}", rusername, username);
        println!("pass: {:?} - {:?}", rpassword, password);
        let builder = hyper::Response::builder()
            .header("WWW-Authenticate", "Basic realm=User Visible Realm")
            .status(hyper::StatusCode::UNAUTHORIZED);
        return Some(
            builder
                .body(hyper::Body::empty())
                .unwrap_or(hyper::Response::default()),
        );
    }

    println!("CREDENTIALS OK {:?} {:?}", &rusername, &rpassword);
    return None;
}

async fn call(
    serv: std::sync::Arc<ServerState>,
    req: hyper::Request<hyper::Body>,
) -> hyper::Response<hyper::Body> {
    println!("call");

    /* if let Some(response) = auth_response(&req, &serv.username, &serv.password) { */
    /*     return response; */
    /* } */

    let workdir =
        std::path::PathBuf::from(ARGS.value_of("dir").expect("missing working directory"));

    let mut cmd = tokio::process::Command::new(ARGS.value_of("cmd").expect("missing cmd"));

    for arg in ARGS.values_of("args").unwrap() {
        cmd.arg(&arg);
    }
    cmd.current_dir(&workdir);
    cmd.env("PATH_INFO", req.uri().path());

    hyper_cgi::do_cgi(req, cmd).await.0
}

#[tokio::main]
async fn main() {
    let username = ""; //ARGS.value_of("username").expect("missing username");
    let password = ""; //ARGS.value_of("password").expect("missing password");
    let server_state = std::sync::Arc::new(ServerState {
        username: username.to_owned(),
        password: password.to_owned(),
    });

    let make_service = hyper::service::make_service_fn(move |_| {
        let server_state = server_state.clone();

        let service = hyper::service::service_fn(move |_req| {
            let server_state = server_state.clone();

            call(server_state, _req).map(Ok::<_, hyper::http::Error>)
        });

        futures::future::ok::<_, hyper::http::Error>(service)
    });

    let addr = format!(
        "0.0.0.0:{}",
        ARGS.value_of("port").unwrap_or("8000").to_owned()
    )
    .parse()
    .unwrap();
    let server = hyper::Server::bind(&addr).serve(make_service);
    println!("Now listening on {}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

fn parse_args() -> clap::ArgMatches<'static> {
    let args = {
        let mut args = vec![];
        for arg in std::env::args() {
            args.push(arg);
        }
        args
    };

    println!("ARGS {:?}", args);

    println!("args: {:?}", args);

    let app = clap::App::new("hyper-cgi-test-server")
        .arg(clap::Arg::with_name("dir").long("dir").takes_value(true))
        .arg(clap::Arg::with_name("cmd").long("cmd").takes_value(true))
        .arg(
            clap::Arg::with_name("args")
                .long("args")
                .short("a")
                .takes_value(true)
                .multiple(true),
        )
        .arg(clap::Arg::with_name("port").long("port").takes_value(true))
        .arg(
            clap::Arg::with_name("password")
                .long("password")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("username")
                .long("username")
                .takes_value(true),
        );

    app.get_matches_from(args)
}
