package main

import (
	"database/sql"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"golang.org/x/crypto/bcrypt"
	"net"
	"regexp"
	"strings"
	"unicode"

	"html/template"
	"net/http"
	//"unicode"
	_ "github.com/go-sql-driver/mysql"
)

//variable declared for template pointer
var tpl *template.Template
//variable declared for db pointer
var db *sql.DB


//functionality of homepage function
func homepage(response http.ResponseWriter, request *http.Request) {
	tpl.ExecuteTemplate(response, "index.html" , nil)
}

//************************************* Register user***************************************************
//functionality to register the user
func registerPpl(response http.ResponseWriter, request *http.Request) {
	fmt.Println("*************register people endpoint hit************")
	tpl.ExecuteTemplate(response ,"landing.html", nil)
}


func authUser(response http.ResponseWriter, request *http.Request) {
	var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	fmt.Println("*************register people authentication endpoint hit************")

	request.ParseForm()

	username := request.FormValue("username")
	password := request.FormValue("password")
	email := request.FormValue("emailID")
	fmt.Println("username:", username)
	fmt.Println("password:", password)
	var nameAlphaNumeric = true

	for _, char := range username{
		if  unicode.IsNumber(char) == false {
			nameAlphaNumeric = false
		}
	}
	var nameLength bool
	if 5 <= len(username) && len(username) <= 50 {
		nameLength = true
	}

	if nameLength && nameAlphaNumeric{
		tpl.ExecuteTemplate(response,"landing.html","Enter valid User name")
		return
	}

	stmt := "SELECT UserID FROM userdb.bcrypt WHERE username = ?"
	row := db.QueryRow(stmt, username)
	var uID string
	err := row.Scan(&uID)
		if err !=sql.ErrNoRows{
			fmt.Println("username already exists, err:", err)
			tpl.ExecuteTemplate(response,"landing.html","username already exists")
			return
	}

	//email validation for correct email id
	if len(email) < 3 && len(email) > 254 {
		tpl.ExecuteTemplate(response,"landing.html","Enter valid EmailId")
		return
	}
	if !emailRegex.MatchString(email) {
		tpl.ExecuteTemplate(response,"landing.html","Enter valid EmailId")
		return
	}
	parts := strings.Split(email, "@")
	mx, err := net.LookupMX(parts[1])
	if err != nil || len(mx) == 0 {
		tpl.ExecuteTemplate(response,"landing.html","Enter valid EmailId")
		return
	}


	var hash []byte
	hash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err !=nil{
		fmt.Println("bcrypt error:", err)
		tpl.ExecuteTemplate(response,"landing.html", "there is problem in registering the account")
		return
	}
	//fmt.Println("hash:", hash)
	//fmt.Println("string(hash):" ,string(hash))

	var insertstmt *sql.Stmt
	insertstmt, err = db.Prepare("INSERT INTO `userdb`.`bcrypt` (`username`, `emailId`, `Hash`) VALUES (?, ?, ?);")
	if err !=nil{
		fmt.Println("error:",err)
		//tpl.ExecuteTemplate(response, "landing.html", "there is problem")
		//return
	}
	defer insertstmt.Close()
	var result sql.Result
	result, err = insertstmt.Exec(username, email, hash)
	rowsAff, _ := result.RowsAffected()
	lastins, _ := result.LastInsertId()
	fmt.Println("row affected:", rowsAff)
	fmt.Println("last inserted:", lastins)
	if err !=nil{
		fmt.Println("error in inserting user")
		fmt.Println("error:",err)
		//tpl.ExecuteTemplate(response, "landing.html", "there was a problem")
		//return
	}
	//fmt.Fprintf(response,"congrats")
	//tpl.ExecuteTemplate(response,"landing.html", )
	tpl.ExecuteTemplate(response, "login.html", nil)
}

//*******************************************login functions ***********************************************

func loginHandler(response http.ResponseWriter, request *http.Request) {
	fmt.Println("************login endpoint hit**************")
	tpl.ExecuteTemplate(response,"login.html", nil )
}

func loginAuthHandler(response http.ResponseWriter, request *http.Request) {
	fmt.Println("************* authentication endpoint hit************")

	request.ParseForm()

	email := request.FormValue("emailID")
	password := request.FormValue("password")
	fmt.Println("username:", email)
	fmt.Println("password:", password)

	var hash string
	stmt := "SELECT Hash FROM userdb.bcrypt WHERE emailId = ?"
	row := db.QueryRow(stmt, email)
	err := row.Scan(&hash)
	fmt.Println("hash from db:", hash)
	if err != nil{
		fmt.Println("error selecting hash from db:",err)
		tpl.ExecuteTemplate(response, "login.html","check emailId and password")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == nil{
		fmt.Fprint(response,"welcome")
		return
	}
	fmt.Println("incorect password")
	tpl.ExecuteTemplate(response,"login.html","check username and password")
}

//***********************************login with google***************************************************

func googleCallbackUrl(response http.ResponseWriter, request *http.Request) {
	user, err := gothic.CompleteUserAuth(response, request)
	if err != nil {
		fmt.Fprintln(response, err)
		return
	}

	var insertstmt *sql.Stmt
	insertstmt, err = db.Prepare("INSERT INTO `userdb`.`bcrypt` (`username`, `emailId`, `Hash`) VALUES (?, ?, ?);")
	if err !=nil{
		fmt.Println("error:",err)
		//tpl.ExecuteTemplate(response, "landing.html", "there is problem")
		//return
	}
	defer insertstmt.Close()

	var result sql.Result

	result, err = insertstmt.Exec(user.Name, user.Email, "")
	rowsAff, _ := result.RowsAffected()
	fmt.Println("row affected:", rowsAff)

	if err !=nil{
		fmt.Println("error in inserting user")
		fmt.Println("error:",err)
		//tpl.ExecuteTemplate(response, "landing.html", "there was a problem")
		//return
	}
	fmt.Println("user:",user)
	//t, _ := template.ParseFiles("templates/success.html")
	tpl.ExecuteTemplate(response,"index.html",nil )
	//t.Execute(response, user)
}
func googleAuthenticator(response http.ResponseWriter, request *http.Request) {
	gothic.BeginAuthHandler(response, request)
}

//***************************************main function****************************************************

//main function start
func main(){

	key := "Secret-session-key"  // Replace with your SESSION_SECRET or similar
	maxAge := 86400 * 30  // 30 days
	isProd := false       // Set to true when serving over https

	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true   // HttpOnly should always be enabled
	store.Options.Secure = isProd

	gothic.Store = store

	goth.UseProviders(
		google.New("1050455121662-6lrf2na16aj6abbu3c14056rffq96hu3.apps.googleusercontent.com", "fDeZ3LHpuTfPwPJLrxbP_c6U", "http://localhost:3000/auth/google/callback", "email", "profile"),
	)

	//tpl is the variable to parse all html template and to access that we use ExecuteTemplate method
	tpl, _ = template.ParseGlob("*.html")

	//setup database
	var err error
	db, err = sql.Open("mysql", "root:manish1234@tcp(localhost:3306)/userdb")
	if err !=nil{
		fmt.Println("there is a error:" , err)
		panic(err.Error())
		fmt.Println("there is a error:" , err)
	}
	defer db.Close()

	router := mux.NewRouter()

	//defined all the restful endpoints
	router.HandleFunc("/", homepage)
	router.HandleFunc("/register" , registerPpl)
	router.HandleFunc("/registerAuth", authUser)
	router.HandleFunc("/login", loginHandler)
	router.HandleFunc("/loginAuth", loginAuthHandler)
	router.HandleFunc("/auth/google/callback", googleCallbackUrl)
	router.HandleFunc("/auth/google", googleAuthenticator)
	//this is to serve the project on port 9004
	http.ListenAndServe(":3000", router)
}










