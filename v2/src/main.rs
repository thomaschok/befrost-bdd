//use actix_web::{web, App,HttpServer, ResponseError};
use serde::{Deserialize};
use askama::Template;
use mysql::*;
use mysql::prelude::*;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
//use actix_web::HttpResponse;
use std::fmt::Debug;
use std::fmt;
use rand::distributions::DistString;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce // Or `Aes128Gcm`
};
use argon2::{self, Config};
use generic_array::{GenericArray, sequence::GenericSequence};

use actix_files::{Files, NamedFile};
use std::{io};
use std::path::{Path, PathBuf};
use actix_web::{
    get,
    http::{
        header::{self, ContentType},
        Method, StatusCode,
    },
    web, App, Either, HttpRequest, HttpResponse, HttpServer, Responder, Result,ResponseError
};

#[derive(Debug)]
pub struct MyError(String); // <-- needs debug and display


//structure d'un password 

#[derive(Debug, PartialEq, Eq)]
struct Password {
    sel_1: String,
    sel_2: String,
    sel_gcm: String,
    clefs: String,
    login: String,
    passw: String,
}



//fonction de hash
impl Hash for Password {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.passw.hash(state);
    }
}



fn salt() -> String {
let mut rng = thread_rng();
let _x: u32 = rng.gen();


let s: String = (&mut rng).sample_iter(Alphanumeric)
    .take(15)
    .map(char::from)
    .collect();
return s;
}



fn passwordhash(a:String ,b: String) -> String {
let password = b.as_bytes();
let salt = a.as_bytes();
let config = Config::default();
let encoded_hash = argon2::hash_encoded(password, salt, &config).unwrap();
let hash = encoded_hash.as_str();
println!("ceci est le hash argon2: {}", hash);
return hash.to_string();
}

fn chiffrement (entree: String, sal: String) -> (String , String) {
let key = Aes256Gcm::generate_key(&mut OsRng);

let mut keystring= "".to_owned();
let vir = " ";
for a in key{
    let cle = a.to_string();
    keystring = keystring + &cle + vir ;
}

let cipher = Aes256Gcm::new(&key);
let mut valeurs   = Vec::new();
let mut crypt ="".to_owned();

//Mettre un sel dans la variable
let salt = sal.as_bytes();
let nonce = Nonce::from_slice(salt); // 96-bits; unique per message

//Mettre l'entréé à chiffrer dans la variable 
let preplain = entree;
let plaintext = preplain.as_bytes();
let ciphertext =cipher.encrypt(nonce, plaintext.as_ref());

match ciphertext{
    Ok(n) => valeurs=n,
    Err(..) => {}
}

for numbers in valeurs{
    let texte = numbers.to_string();
    crypt=crypt+&texte;
}
//La sortie est crypt, il s'agit d'un string correspondant à une suite de chiffre 
println!("{}", crypt);
return (crypt,keystring);
}







fn dechiffrement (ki: String , entree: String, sal: String) -> String {
let result: Vec<&str> = ki.split(" ").collect();
let mut array = GenericArray::generate(|i: usize| i as u8);
    let mut i = 0;
    for a in result{
    	if i<32{
    		let my_string = a.to_string();
    		let my_int= my_string.parse::<u8>().unwrap();
    		array[i] = my_int;
    		i = i+1;
    	}
    }
    
let cipher = Aes256Gcm::new(&array);
let mut valeurs   = Vec::new();
let mut crypt ="".to_owned();

//Mettre un sel dans la variable
let salt = sal.as_bytes();
let nonce = Nonce::from_slice(salt); // 96-bits; unique per message

//Mettre l'entréé à chiffrer dans la variable 
let preplain = entree;
let plaintext = preplain.as_bytes();
let ciphertext =cipher.encrypt(nonce, plaintext.as_ref());

match ciphertext{
    Ok(n) => valeurs=n,
    Err(..) => {}
}

for numbers in valeurs{
    let texte = numbers.to_string();
    crypt=crypt+&texte;
}
//La sortie est crypt, il s'agit d'un string correspondant à une suite de chiffre 
println!("{}", crypt);
return crypt;
}
/////////////////////////////////////////////////////////////////////////////



impl fmt::Display for MyError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let c = formatter.fill();
        if let Some(width) = formatter.width() {
            for _ in 0..width {
                write!(formatter, "{c}")?;
            }
            Ok(())
        } else {
            write!(formatter, "{c}")
        }
    }
}
 

impl ResponseError for MyError {} // <-- key // je crée l'instance erreur avec la macro du dessus


#[derive(Debug, Template)] //déclaration de la 1ére template html (le formulaire)
#[template(path = "index.html")]
struct Index {}

#[derive(Debug, Template)] // déclaration de la 2éme template html (affichage de la variable)
#[template(path = "show.html")]
struct Show {
    thing_to_show:String,
    thing_to_show2:String,
    thing_to_show3:String,
}



#[derive(Debug, Deserialize)] // pour adapter la donnée
struct FormData {
    thing_to_show:String,
    thing_to_show2:String,
    thing_to_show3:String,
}

//////////////////////////////////
async fn default_handler(req_method: Method) -> Result<impl Responder> {
    match req_method {
        Method::GET => {
            let file = NamedFile::open("templates/404.html")?
                .customize()
                .with_status(StatusCode::NOT_FOUND);
            Ok(Either::Left(file))
        }
        _ => Ok(Either::Right(HttpResponse::MethodNotAllowed().finish())),
    }
}



async fn showthis(form_data: web::Form<FormData>) -> Result<NamedFile> { //fonction pour afficher le 2éme rendu html
    let html = Show{ thing_to_show: form_data.thing_to_show.to_string(),thing_to_show2: form_data.thing_to_show2.to_string(),thing_to_show3: form_data.thing_to_show3.to_string()}.render().unwrap();
    println!("{}",html);
    let path: PathBuf = "templates/menushowthis.html".parse().unwrap();
    Ok(NamedFile::open(path)?)
}



/*
#[get("templates/menu1")]
async fn menu1(req: HttpRequest) -> Result<HttpResponse> {
    println!("{req:?}");
    // response
    Ok(HttpResponse::build(StatusCode::OK)
        .content_type(ContentType::plaintext())
        .body(include_str!("../templates/menu1.html")))
}*/

async fn index(data: web::Data<String>) -> HttpResponse {
    let html = format!(r#"
    <html>
        <body>
            <script src="/templates/sha256.js" type="text/javascript"></script>
            <link rel="stylesheet" type="text/css" href="/templates/SignUp.css" />
            <script src="/templates/lottie-player.js" type="text/javascript"></script>
            <script>
                var rust_variable = '{}';
                document.getElementById('rust_variable_value').innerHTML = rust_variable; 
                console.log(rust_variable)
                
            function Securisation() {{
                let str;
                str = document.getElementById("password").value;
                console.log(str.length);
                console.log(str);
                let mdphash = str+rust_variable;
                console.log (mdphash)
                let hash = sha256(mdphash)
		        console.log(hash);
            }}                  
            </script>
            <body class="body">     
      <div class="login-page">
        <div class="form">
		<div class="titre">
		<h1 align="center">SIGNUP BIFROST</h1>
	</div>
          <form>
            <lottie-player
              src="https://assets4.lottiefiles.com/datafiles/XRVoUu3IX4sGWtiC3MPpFnJvZNq7lVWDCa8LSqgS/profile.json"
              background="transparent"
              speed="1"
              style="justify-content: center"
              loop
              autoplay
            ></lottie-player>
            <input id="login" type="text" placeholder="&#xf007; Login" />
            <input id="password" type="password"  placeholder="&#xf023; Password" />          </form>
			
		<a><input id="signup" type="submit" value="SIGN UP"  style="display: none;" ><a>
          <a><input id="test" type="button" onclick="Securisation()"value="Verification du mot de passe"><a>
          <button onclick="window.location.href='templates/menu1.html'">ok</button>
        </div>
      </div>
        </body>
    </html>
"#, data.get_ref());
    HttpResponse::Ok().content_type("text/html").body(html)
}

///////////////////////////////

impl std::fmt::Display for FormData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FormData")
         .field("thing_to_show", &self.thing_to_show)
         .finish()
    }
}

/*
async fn index() ->std::result::Result<HttpResponse, Box<dyn std::error::Error>> { //fonction pour afficher le premier rendu html
    let html = Index{}.render().unwrap();
    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

*/

/*
async fn menu() -> std::result::Result<HttpResponse, Box<dyn std::error::Error>> {
	let  home = Index{}.render().unwrap();
	Ok(HttpResponse::Ok().content_type("menu/html").body(home))
}
*/




/*
async fn showthis(form_data: web::Form<FormData>) -> String  { //fonction pour afficher le 2éme rendu html
    let html = Show{ thing_to_show: form_data.thing_to_show.to_string() }.render().unwrap();
    println!("{}",html);
    let y= salt();
    println!("{}",y);
    let concat = html + &y.to_string();
    println!("{}",concat);
    let x = passwordhash(concat);
    println!("{}",x);
    return x;


}

*/

/*async fn cequetuveux() -> String{
    let formdata = FormData { thing_to_show: String::new() };
    let data = showthis(actix_web::web::Form(formdata)).await.to_string();
    //let up = data;
    println!("{}", data);
    let y= salt();
    let concat = data + &y.to_string();
    let x = passwordhash(concat);
    return x;
}

*/

/*
#[actix_web::main]
async fn main() -> std::io::Result<()> {
        HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(index))
            .route("/showthis", web::post().to(bdd_create))
            
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
    
}

*/


#[actix_web::main]
async fn main() -> io::Result<()> {
    HttpServer::new(move || {
        App::new()
        //.service(menu1) 
         // static files
        .service(Files::new("/templates", "templates").show_files_listing())
            // redirect
        .service(
                web::resource("/templates/login.html").route(web::get().to(|req: HttpRequest| async move {
                    //println!("{req:?}");
                    HttpResponse::Found()
                        .insert_header((header::LOCATION, "templates/login.html"))
                        .finish()
                })),
            )
            // default
        .default_service(web::to(default_handler))
         .route("/showthis", web::post().to(bdd_authentification))
        .data("Salt".to_owned()).route("/", web::get().to(index))
    })
    .bind(("127.0.0.1", 1025))?
    .workers(2)
    .run()
    .await
}




async fn bdd_create(form_data: web::Form<FormData>) -> std::result::Result<HttpResponse, Box<dyn std::error::Error>>{
    let url = "mysql://GAGA:mypass@localhost:3306/passwd";
    let pool = Pool::new(url)?;
    let mut conn = pool.get_conn()?;
    let hashlolo = form_data.thing_to_show.to_string();    
    let log = form_data.thing_to_show2.to_string();    
    let sellolo= form_data.thing_to_show3.to_string();
    let y= salt();
    let sel= y.clone();
    let concat = hashlolo + &y.to_string();
    let x = passwordhash(y, concat);
    let presalt = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
    let salt_gcm = presalt.clone();
    let (aes , key) = chiffrement(x , presalt);
    println!("{} chiffrement aes:", aes);
    println!("{} la clefffffffff", key);
  	
    conn.query_drop(
        r"CREATE TABLE IF NOT EXISTS password (
            sel_1 text not null,
            sel_2 text not null,
            sel_gcm text not null,
            clefs text not null,
            login text not null,
            password text not null
        )")?;
    let _passwords = vec![
        Password { sel_1: sellolo  , sel_2:sel , sel_gcm:salt_gcm , clefs:key,  login: log , passw: aes },
    ];


    conn.exec_batch(
        r"INSERT INTO password (sel_1, sel_2, sel_gcm, clefs, login, password)
          VALUES (:sel_1, :sel_2, :sel_gcm, :clefs, :login, :password)",
        _passwords.iter().map(|p| params! {
            "sel_1" => &p.sel_1,
            "sel_2" => &p.sel_2,
            "sel_gcm" => &p.sel_gcm,
            "clefs" => &p.clefs,
            "login" => &p.login,
            "password" => &p.passw,
        })
    )?;
Ok(HttpResponse::Ok().content_type("text/html").body("super"))
 
 }
 



async fn bdd_research(form_data: web::Form<FormData>)->std::result::Result<HttpResponse, Box<dyn std::error::Error>>{

    let url = "mysql://GAGA:mypass@localhost:3306/passwd";
    let pool = Pool::new(url)?;
    let mut conn = pool.get_conn()?;
    let hashlolo = form_data.thing_to_show.to_string();    
    let log = form_data.thing_to_show2.to_string();    
    let sellolo= form_data.thing_to_show3.to_string();
    let y= salt();
    let sel = y.clone();
    let concat = hashlolo + &y.to_string();
    let x = passwordhash(y , concat);
    let presalt = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
    let salt_gcm = presalt.clone();
    let (aes , key) = chiffrement(x , presalt);

    
     let _passwords = vec![
        Password { sel_1: sellolo  , sel_2:sel , sel_gcm:salt_gcm, clefs:key,  login: log , passw: aes },
    ];
    
    
let selected_passwords = conn
    	.query_map(
            "SELECT * FROM password where login='thomas' ",
            |(sel_1, sel_2, sel_gcm, clefs, login, passw)| {
                Password { sel_1, sel_2, sel_gcm, clefs, login, passw }
            },
        )?;

let mut log_extrait = "".to_string();

for burnout in selected_passwords {
log_extrait.push_str(&burnout.sel_1);

}


println!("{}", log_extrait);


//assert_eq!(selected_passwords, _passwords);

		
	
Ok(HttpResponse::Ok().content_type("text/html").body("super"))
 
}	



async fn bdd_authentification(form_data: web::Form<FormData>)->std::result::Result<HttpResponse, Box<dyn std::error::Error>>{
	let url = "mysql://GAGA:mypass@localhost:3306/passwd";
	let pool = Pool::new(url)?;
	let mut conn = pool.get_conn()?;
	
	
	let selected_passwords = conn
    	.query_map(
            "SELECT * FROM password where login='thomas' ",
            |(sel_1, sel_2, sel_gcm, clefs, login, passw)| {
                Password { sel_1, sel_2, sel_gcm, clefs, login, passw }
            },
        )?;


	let selected_passwords2 = conn
    	.query_map(
            "SELECT * FROM password where login='thomas' ",
            |(sel_1, sel_2, sel_gcm, clefs, login, passw)| {
                Password { sel_1, sel_2, sel_gcm, clefs, login, passw }
            },
        )?;
        
        
        	let selected_passwords3 = conn
    	.query_map(
            "SELECT * FROM password where login='thomas' ",
            |(sel_1, sel_2, sel_gcm, clefs, login, passw)| {
                Password { sel_1, sel_2, sel_gcm, clefs, login, passw }
            },
        )?;
        
        
                	let selected_passwords4 = conn
    	.query_map(
            "SELECT * FROM password where login='thomas' ",
            |(sel_1, sel_2, sel_gcm, clefs, login, passw)| {
                Password { sel_1, sel_2, sel_gcm, clefs, login, passw }
            },
        )?;
        
        
                	let selected_passwords5 = conn
    	.query_map(
            "SELECT * FROM password where login='thomas' ",
            |(sel_1, sel_2, sel_gcm, clefs, login, passw)| {
                Password { sel_1, sel_2, sel_gcm, clefs, login, passw }
            },
        )?;
        

let mut log_extrait_sel_web = "".to_string();
let mut log_extrait_sel_backend = "".to_string();
let mut log_extrait_password = "".to_string();
let mut log_extrait_sel_gcm = "".to_string();
let mut log_extrait_clefs_aes = "".to_string();

for burnout in selected_passwords {
log_extrait_sel_web.push_str(&burnout.sel_1);
}

for salting in selected_passwords2 {
log_extrait_sel_backend.push_str(&salting.sel_2);
}

for motdepasse in selected_passwords3 {
log_extrait_password.push_str(&motdepasse.passw);
}

for gcmsuite in selected_passwords4 {
log_extrait_sel_gcm.push_str(&gcmsuite.sel_gcm);
}

for aesfinit in selected_passwords5 {
log_extrait_clefs_aes.push_str(&aesfinit.clefs);
}

println!("ceci est le sel 1: {}", log_extrait_sel_web);
println!("ceci est le sel 2: {}", log_extrait_sel_backend);
println!("ceci est le password: {}", log_extrait_password);
println!("ceci est le sel-gcm: {}", log_extrait_sel_gcm);
println!("ceci est la clef-gcm: {}", log_extrait_clefs_aes);

    let hashlolo = form_data.thing_to_show.to_string();    
    let log = form_data.thing_to_show2.to_string();    
    let sellolo= log_extrait_sel_web ;
    let y= log_extrait_sel_backend;
    let concat = hashlolo + &y.to_string();
    let x = passwordhash(y ,concat);
    let aes = dechiffrement(log_extrait_clefs_aes, x , log_extrait_sel_gcm); 
    
    
    
    println!("ceci est le password entrée: {}", aes);   
        
    
    assert_eq!(log_extrait_password, aes);

		
	
Ok(HttpResponse::Ok().content_type("test/html").body("super"))

}



	