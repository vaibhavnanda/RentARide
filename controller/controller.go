package controller

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"RentARide/model"

	"github.com/go-co-op/gocron"
	"github.com/mitchellh/mapstructure"
	"github.com/patrickmn/go-cache"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// var tpl = template.Must(template.ParseGlob("templates/*"))

var tpl = template.Must(template.New("").Funcs(template.FuncMap{
	"ConvertTimeToString": ConvertTimeToString,
}).ParseGlob("templates/*"))

func HelperFunc(a string) string {
	return a
}

var cacheVar = cache.New(48*time.Hour, 2*time.Hour)

type UserController struct {
	session *mgo.Session
}

func NewUserController(s *mgo.Session) *UserController {
	return &UserController{s}
}

var Uc = NewUserController(GetSession())

func GetSession() *mgo.Session {
	s, err := mgo.Dial("mongodb://localhost")

	if err != nil {
		panic(err)
	}
	return s
}

// Func to check if a username has already been taken
func UsernameExistsOrNot(username string, collection string) bool {
	n, err := Uc.session.DB("rentaride").C(collection).Find(bson.M{"username": username}).Count()
	if err != nil {
		log.Fatal(err)
	} else if n == 1 {
		return true
	}
	return false
}

// Func to check if the rider is logged in or not, and also returns the user info if logged in
func riderLoggedInOrNot(r *http.Request) (model.Rider, error) {
	rsession, err := r.Cookie("rsession")
	if err != nil {
		return model.Rider{}, err
	}

	sid := rsession.Value //rsession value

	// For extracting username corresponding to the sid
	var username struct {
		Username string `bson:"username"`
	}

	var usernameVal string
	sessionCache, found := cacheVar.Get("rider_" + sid) // Extracting username value corresponding to a session id in cache

	// If username val is found in cache
	if found {
		// Using mapstructure to convert interface{} to string
		mapstructure.Decode(sessionCache, &usernameVal)
		username.Username = usernameVal
	} else {

		// If value not found in cache, then find in the db
		err = Uc.session.DB("rentaride").C("ridersession").Find(bson.M{"sid": sid}).One(&username)
		if err != nil {
			log.Fatal(err)
		}

		// Setting the sid username pair in cache
		cacheVar.Set("rider_"+sid, username.Username, 0)
	}

	user := model.Rider{}

	// Retrieving user data corresponding to the username we found
	err = Uc.session.DB("rentaride").C("rider").Find(bson.M{"username": username.Username}).One(&user)
	if err != nil {
		log.Fatal(err)
	}

	return user, nil
}

// Func to check if the provider is logged in or not, and also returns the user info if logged in
func providerLoggedInOrNot(r *http.Request) (model.Provider, error) {
	psession, err := r.Cookie("psession")
	if err != nil {
		return model.Provider{}, err
	}

	sid := psession.Value //psession value

	// For extracting username corresponding to the sid
	var username struct {
		Username string `bson:"username"`
	}

	var usernameVal string
	sessionCache, found := cacheVar.Get("provider_" + sid) // Extracting username value corresponding to a session id in cache

	// If username val is found in cache
	if found {
		// Using mapstructure to convert interface{} to string
		mapstructure.Decode(sessionCache, &usernameVal)
		username.Username = usernameVal
	} else {

		// If value not found in cache, then find in the db
		err = Uc.session.DB("rentaride").C("providersession").Find(bson.M{"sid": sid}).One(&username)
		if err != nil {
			log.Fatal(err)
		}

		// Setting the sid username pair in cache
		cacheVar.Set("provider_"+sid, username.Username, 0)
	}

	user := model.Provider{}

	// Retrieving user data corresponding to the username we found
	err = Uc.session.DB("rentaride").C("provider").Find(bson.M{"username": username.Username}).One(&user)
	if err != nil {
		log.Fatal(err)
	}

	return user, nil
}

// Func to check if vehicle info is valid or not
func VehicleValidation(r *http.Request) string {
	var data string
	if strings.TrimSpace(r.FormValue("numberplate")) == "" {
		data = "Please enter Number plate."
		return data
	}
	if strings.TrimSpace(r.FormValue("wheels")) == "" {
		data = "Please enter Vehicle Type."
		return data
	}
	if strings.TrimSpace(r.FormValue("name")) == "" {
		data = "Please enter Vehicle Name."
		return data
	}
	if strings.TrimSpace(r.FormValue("location")) == "" {
		data = "Please enter Address."
		return data
	}

	numberPlateStripped := strings.TrimSpace(r.FormValue("numberplate"))
	if isNumberPlateValid, _ := regexp.MatchString("^[A-Z]{2}[ -][0-9]{1,2}(?: [A-Z])?(?: [A-Z]*)? [0-9]{4}$", numberPlateStripped); !isNumberPlateValid {
		data = "Number Plate invalid."
		return data
	}

	// Check if the number plate already exists in our db
	count, _ := Uc.session.DB("rentaride").C("takennumberplates").Find(bson.M{"numberplate": numberPlateStripped}).Count()
	if count == 1 {
		data = "Number Plate already registered with the app."
		return data
	}

	return data
}

// Func to validate rider sign up values
func RiderValidation(r *http.Request) string {
	var data string
	if strings.TrimSpace(r.FormValue("username")) == "" {
		data = "Please enter Username."
		return data
	}
	if r.FormValue("password") == "" {
		data = "Please enter Password."
		return data
	}
	if strings.TrimSpace(r.FormValue("name")) == "" {
		data = "Please enter Name."
		return data
	}
	if strings.TrimSpace(r.FormValue("address")) == "" {
		data = "Please enter Address."
		return data
	}
	if strings.TrimSpace(r.FormValue("dl")) == "" {
		data = "Please enter Driver's License number."
		return data
	}
	if strings.TrimSpace(r.FormValue("phone")) == "" {
		data = "Please enter Phone."
		return data
	}
	if usernameExistence := UsernameExistsOrNot(r.FormValue("username"), "rider"); usernameExistence == true {
		data = "Username already exists."
		return data
	}
	dlStripped := strings.TrimSpace(r.FormValue("dl"))
	if isDlValid, _ := regexp.MatchString("^[a-zA-z][a-zA-z][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$", dlStripped); !isDlValid {
		data = "Driver's License format doesn't match."
		return data
	}
	phoneStripped := strings.TrimSpace(r.FormValue("phone"))
	if isPhoneValid, _ := regexp.MatchString("^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$", phoneStripped); !isPhoneValid {
		data = "Phone number must be of 10 digits"
		return data
	}
	return data
}

// Func to validate provider sign up values
func ProviderValidation(r *http.Request) string {
	var data string
	if r.FormValue("username") == "" {
		data = "Please enter Username."
		return data
	}
	if r.FormValue("password") == "" {
		data = "Please enter Password."
		return data
	}
	if r.FormValue("name") == "" {
		data = "Please enter Name."
		return data
	}
	if r.FormValue("address") == "" {
		data = "Please enter Address."
		return data
	}
	if r.FormValue("adhaar") == "" {
		data = "Please enter Adhaar number."
		return data
	}
	if r.FormValue("phone") == "" {
		data = "Please enter Phone."
		return data
	}
	if usernameExistence := UsernameExistsOrNot(r.FormValue("username"), "provider"); usernameExistence == true {
		data = "Username already exists."
		return data
	}
	adhaarStripped := strings.TrimSpace(r.FormValue("adhaar"))
	if isAdhaarValid, _ := regexp.MatchString("^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$", adhaarStripped); !isAdhaarValid {
		data = "Adhaar number format doesn't match."
		return data
	}
	phoneStripped := strings.TrimSpace(r.FormValue("phone"))
	if isPhoneValid, _ := regexp.MatchString("^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$", phoneStripped); !isPhoneValid {
		data = "Phone number must be of 10 digits"
		return data
	}
	return data
}

// Func to Insert image in the db gridfs
func InsertImage(file multipart.File, fileName string) {
	file1, err := Uc.session.DB("imagedb").GridFS("images").Create(fileName)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer file.Close()
	dataFile1, _ := ioutil.ReadAll(file)
	_, err2 := file1.Write(dataFile1)
	if err2 != nil {
		log.Fatal(err2)
		return
	}
	file1.Close()
}

// Get an image url from the string stored in the db gridfs
func GetImage(name string) string {
	file1, err := Uc.session.DB("imagedb").GridFS("images").Open(name)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file1.Close()

	tempFile1, _ := os.Create("tempFile1")

	defer tempFile1.Close()

	io.Copy(tempFile1, file1)

	data1, _ := os.Open("tempFile1")

	// // Read entire JPG into byte slice.
	reader1 := bufio.NewReader(data1)

	content1, _ := ioutil.ReadAll(reader1)

	// // // Encode as base64.
	encoded1 := base64.StdEncoding.EncodeToString(content1)
	return encoded1
}

// Converting a string value from form to time.Time
func convertingTime(s string) time.Time {
	y, _ := strconv.Atoi(s[:4])
	m, _ := strconv.Atoi(s[5:7])
	d, _ := strconv.Atoi(s[8:10])
	hr, _ := strconv.Atoi(s[11:13])
	min, _ := strconv.Atoi(s[14:16])

	loc, _ := time.LoadLocation("Asia/Kolkata")
	return time.Date(y, time.Month(m), d, hr, min, 0, 0, loc)
}

// Finding the number of hours between the starting time and the ending time
func gettingHours(start, end time.Time) int {
	dur := end.Sub(start)
	hrs := dur.Hours()
	floatHrs := math.Ceil(hrs)
	intHrs := int(floatHrs)
	return intHrs
}

func ConvertTimeToString(timeObj time.Time) string {
	datetime := timeObj.String()
	tempDateVal := datetime[:10]
	dateVal := tempDateVal[8:10] + "-" + tempDateVal[5:7] + "-" + tempDateVal[0:4]
	timeVal := datetime[11:16] + " "
	return timeVal + dateVal
}

// Func to update the availablevehicles collection to remove all the vehicles with end time less than the current time
func UpdateAvailableVehicles() {
	curTime := time.Now()
	Uc.session.DB("rentaride").C("availablevehicles").RemoveAll(bson.M{"endtime": bson.M{"$lt": curTime}})

	var providersSlice []model.Provider
	Uc.session.DB("rentaride").C("provider").Find(nil).All(&providersSlice)

	for _, val := range providersSlice {
		newProvider := val
		avlVehicleSliceNew := make([]model.AvailableVehicleProvider, 0)
		for _, v := range val.AvailableVehicleSlice {
			if v.EndTime.After(curTime) {
				avlVehicleSliceNew = append(avlVehicleSliceNew, v)
			}
		}
		newProvider.AvailableVehicleSlice = avlVehicleSliceNew

		Uc.session.DB("rentaride").C("provider").Update(val, newProvider)
	}
}

// Calling the UpdateAvailableVehicles func every 10 minutes
func ScheduleUpdates() {
	loc, _ := time.LoadLocation("Asia/Kolkata")
	s1 := gocron.NewScheduler(loc)
	s1.Every(1).Minutes().Do(UpdateAvailableVehicles)
	s1.StartAsync()
}

// Home page
func Index(w http.ResponseWriter, r *http.Request) {

	if _, err := riderLoggedInOrNot(r); err == nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if _, err := providerLoggedInOrNot(r); err == nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	tpl.ExecuteTemplate(w, "index.html", nil)
}

// Rider login page
func RiderLogin(w http.ResponseWriter, r *http.Request) {

	if _, err := riderLoggedInOrNot(r); err == nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if _, err := providerLoggedInOrNot(r); err == nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodGet {
		var val string
		val = r.FormValue("q")
		tpl.ExecuteTemplate(w, "riderlogin.html", val)
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		if strings.TrimSpace(username) == "" {
			tpl.ExecuteTemplate(w, "riderlogin.html", "Please enter Username.")
			return
		}

		password := r.FormValue("password")
		if password == "" {
			tpl.ExecuteTemplate(w, "riderlogin.html", "Please enter Password.")
			return
		}

		if usernameExistence := UsernameExistsOrNot(username, "rider"); !usernameExistence {
			tpl.ExecuteTemplate(w, "riderlogin.html", "Username doesn't exist.")
			return
		}

		var pwdFromDb struct {
			Pass []byte `bson:"password"`
		}

		err := Uc.session.DB("rentaride").C("rider").Find(bson.M{"username": username}).Select(bson.M{"password": 1}).One(&pwdFromDb)
		if err != nil {
			log.Fatal(err)
		}

		err = bcrypt.CompareHashAndPassword(pwdFromDb.Pass, []byte(password))
		if err != nil {
			tpl.ExecuteTemplate(w, "riderlogin.html", "Wrong Password.")
			return
		}

		sid := uuid.NewV4()
		http.SetCookie(w, &http.Cookie{
			Name:  "rsession",
			Value: sid.String(),
		})

		curSession := model.Rsession{
			Id:       bson.NewObjectId(),
			Sid:      sid.String(),
			Username: username,
		}
		Uc.session.DB("rentaride").C("ridersession").Insert(curSession)

		http.Redirect(w, r, "/riderhome", http.StatusFound)
		// tpl.ExecuteTemplate(w, "riderhome.html", nil)

	}
}

// Provider login page
func ProviderLogin(w http.ResponseWriter, r *http.Request) {

	if _, err := riderLoggedInOrNot(r); err == nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if _, err := providerLoggedInOrNot(r); err == nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodGet {
		var val string
		val = r.FormValue("q")
		tpl.ExecuteTemplate(w, "providerlogin.html", val)
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		if username == "" {
			tpl.ExecuteTemplate(w, "providerlogin.html", "Please enter Username.")
			return
		}

		password := r.FormValue("password")
		if password == "" {
			tpl.ExecuteTemplate(w, "providerlogin.html", "Please enter Password.")
			return
		}

		if usernameExistence := UsernameExistsOrNot(username, "provider"); !usernameExistence {
			tpl.ExecuteTemplate(w, "providerlogin.html", "Username doesn't exist.")
			return
		}

		var pwdFromDb struct {
			Pass []byte `bson:"password"`
		}

		err := Uc.session.DB("rentaride").C("provider").Find(bson.M{"username": username}).Select(bson.M{"password": 1}).One(&pwdFromDb)
		if err != nil {
			log.Fatal(err)
		}

		err = bcrypt.CompareHashAndPassword(pwdFromDb.Pass, []byte(password))
		if err != nil {
			tpl.ExecuteTemplate(w, "providerlogin.html", "Wrong Password.")
			return
		}

		// Setting cookie for sessions
		sid := uuid.NewV4()
		http.SetCookie(w, &http.Cookie{
			Name:  "psession",
			Value: sid.String(),
		})

		curSession := model.Psession{
			Id:       bson.NewObjectId(),
			Sid:      sid.String(),
			Username: username,
		}
		Uc.session.DB("rentaride").C("providersession").Insert(curSession)

		http.Redirect(w, r, "/providerhome", http.StatusFound)
	}
}

// Rider Login page
func RiderLogout(w http.ResponseWriter, r *http.Request) {

	if _, err := riderLoggedInOrNot(r); err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	// cookie deletion process
	rsession, err := r.Cookie("rsession")
	if err != nil {
		http.Error(w, "Cookie doesn't exist", 404)
		return
	}
	rsession.MaxAge = -1
	sid := rsession.Value
	http.SetCookie(w, rsession)

	// delete session details from ridersession collection
	err = Uc.session.DB("rentaride").C("ridersession").Remove(bson.M{"sid": sid})
	if err != nil {
		http.Error(w, "Remove fail", 404)
		return
	}

	http.Redirect(w, r, "/", 302)
}

// Provider Login page
func ProviderLogout(w http.ResponseWriter, r *http.Request) {

	if _, err := providerLoggedInOrNot(r); err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	// cookie deletion process
	psession, err := r.Cookie("psession")
	if err != nil {
		http.Error(w, "Cookie doesn't exist", 404)
		return
	}
	psession.MaxAge = -1
	sid := psession.Value
	http.SetCookie(w, psession)

	// delete session details from providersession collection
	err = Uc.session.DB("rentaride").C("providersession").Remove(bson.M{"sid": sid})
	if err != nil {
		http.Error(w, "Remove fail", 404)
		return
	}

	http.Redirect(w, r, "/", 302)
}

// Rider signup page
func RiderSignup(w http.ResponseWriter, r *http.Request) {

	if _, err := riderLoggedInOrNot(r); err == nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if _, err := providerLoggedInOrNot(r); err == nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodGet {
		tpl.ExecuteTemplate(w, "ridersignup.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		tempId := bson.NewObjectId()
		isValidated := RiderValidation(r)

		bookings := make([]model.RentedVehicleInfo, 0)
		pwd := r.FormValue("password")
		hashedPwd, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.MinCost)
		user := model.Rider{
			Id:         tempId,
			Username:   strings.TrimSpace(r.FormValue("username")),
			Password:   hashedPwd,
			Name:       strings.TrimSpace(r.FormValue("name")),
			Address:    strings.TrimSpace(r.FormValue("address")),
			Dl:         r.FormValue("dl"),
			Phone:      r.FormValue("phone"),
			Bookings:   bookings,
			RedeemInfo: make([]model.Redeem, 0),
		}

		// var data is kept so that the form values are not deleted when a field's value is not according to the format
		data := struct {
			FormData  model.Rider
			Info      string
			StringPwd string
		}{
			user,
			isValidated,
			pwd,
		}

		if isValidated != "" {
			tpl.ExecuteTemplate(w, "ridersignup.html", data)
			return
		}

		Uc.session.DB("rentaride").C("rider").Insert(user) // Inserting to db

		http.Redirect(w, r, "/riderlogin?q=Successfully%20Signed%20Up", http.StatusFound)
		return

	}
}

// Provider signup page
func ProviderSignup(w http.ResponseWriter, r *http.Request) {

	if _, err := riderLoggedInOrNot(r); err == nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if _, err := providerLoggedInOrNot(r); err == nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodGet {
		tpl.ExecuteTemplate(w, "providersignup.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		tempId := bson.NewObjectId()
		isValidated := ProviderValidation(r)

		vehicles := make([]model.Vehicle, 0)
		availableVehicleSlice := make([]model.AvailableVehicleProvider, 0)
		bookings := make([]model.RentedVehicleInfo, 0)
		pwd := r.FormValue("password")
		hashedPwd, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.MinCost)
		user := model.Provider{
			Id:                    tempId,
			Username:              strings.TrimSpace(r.FormValue("username")),
			Password:              hashedPwd,
			Name:                  strings.TrimSpace(r.FormValue("name")),
			Address:               strings.TrimSpace(r.FormValue("address")),
			Adhaar:                r.FormValue("adhaar"),
			Phone:                 r.FormValue("phone"),
			Vehicles:              vehicles,
			AvailableVehicleSlice: availableVehicleSlice,
			Bookings:              bookings,
			RedeemInfo:            make([]model.Redeem, 0),
		}

		// var data is kept so that the form values are not deleted when a field's value is not according to the format
		data := struct {
			FormData  model.Provider
			Info      string
			StringPwd string
		}{
			user,
			isValidated,
			pwd,
		}

		if isValidated != "" {
			tpl.ExecuteTemplate(w, "providersignup.html", data)
			return
		}

		Uc.session.DB("rentaride").C("provider").Insert(user) // Inserting to db

		http.Redirect(w, r, "/providerlogin?q=Successfully%20Signed%20Up", http.StatusFound)
		return
	}
}

// Rider home page
func RiderHome(w http.ResponseWriter, r *http.Request) {

	user, err := riderLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	tpl.ExecuteTemplate(w, "riderhome.html", user)
}

// Provider home page
func ProviderHome(w http.ResponseWriter, r *http.Request) {

	user, err := providerLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	tpl.ExecuteTemplate(w, "providerhome.html", user)
}

// Providers adding vehicle
func AddVehicle(w http.ResponseWriter, r *http.Request) {
	user, err := providerLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodGet {
		tpl.ExecuteTemplate(w, "addvehicle.html", nil)
		return
	}

	if r.Method == http.MethodPost {

		// Check if all the fields are valid or not
		// Keep a struct to store the form values in case some of the values are invalid
		if isVehicleValid := VehicleValidation(r); isVehicleValid != "" {
			FormData := struct {
				NumberPlate string
				Wheels      string
				Name        string
				Location    string
				Info        string
			}{
				strings.TrimSpace(r.FormValue("numberplate")),
				r.FormValue("wheels"),
				strings.TrimSpace(r.FormValue("name")),
				strings.TrimSpace(r.FormValue("location")),
				isVehicleValid,
			}
			tpl.ExecuteTemplate(w, "addvehicle.html", FormData)
			return
		}

		newVehicles := user.Vehicles // All the stored vehicles

		var imageSlice []string // To store image names (UUID) that are to be stored in the db

		// Extracting image files from the form
		for i := 1; i <= 5; i++ {
			name := "img" + strconv.Itoa(i)
			file, _, err := r.FormFile(name)
			if err != nil {
				continue
			}

			imgName := uuid.NewV4() // Using a UUID as an image name

			imageSlice = append(imageSlice, imgName.String())

			// Insert the images in the db
			InsertImage(file, imgName.String())
		}

		// New Vehicle info
		vehicleInfo := model.Vehicle{
			Id:               bson.NewObjectId(),
			NumberPlate:      strings.TrimSpace(r.FormValue("numberplate")),
			Wheels:           r.FormValue("wheels"),
			Name:             strings.TrimSpace(r.FormValue("name")),
			ProviderUsername: user.Username,
			Location:         strings.TrimSpace(r.FormValue("location")),
			ImageNames:       imageSlice,
		}

		// Adding the new vehicle to the slice of old vehicles
		newVehicles = append(newVehicles, vehicleInfo)

		newUserInfo := user
		newUserInfo.Vehicles = newVehicles

		// Updating the provider's info
		Uc.session.DB("rentaride").C("provider").Update(user, newUserInfo)

		// Add the number plate to the db for maintaining the uniqueness of the vehicles
		numberPlateData := model.TakenNumberPlates{
			Id:          bson.NewObjectId(),
			NumberPlate: vehicleInfo.NumberPlate,
		}
		Uc.session.DB("rentaride").C("takennumberplates").Insert(numberPlateData)

		http.Redirect(w, r, "/providerhome", http.StatusFound)
		return

	}
}

// Vehicle info for providers
func VehicleInfo(w http.ResponseWriter, r *http.Request) {

	user, err := providerLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodGet {

		numberPlateVal := r.FormValue("numberplate") // Reqd vehicle's number plate

		vehicleSlice := user.Vehicles

		ReqdVehicle := model.Vehicle{}

		// Extracting the reqd vehicle's info from the provider's info
		for _, val := range vehicleSlice {
			if val.NumberPlate == numberPlateVal {
				ReqdVehicle = val
				break
			}
		}

		if ReqdVehicle.NumberPlate == "" {
			http.Error(w, "You can't visit this page.", 404)
			return
		}

		imageNames := ReqdVehicle.ImageNames // Image UUIDs of the vehicle

		var encodedImages []string // To store the encoded Image URLs

		for _, v := range imageNames {
			encoded := GetImage(v)
			encodedImages = append(encodedImages, encoded)
		}

		Data := struct {
			User model.Provider
			Reqd model.Vehicle
			Imgs []string
		}{
			user,
			ReqdVehicle,
			encodedImages,
		}

		tpl.ExecuteTemplate(w, "vehicleinfo.html", Data)
		return
	}
}

// For deleting the vehicle
func VehicleDeletion(w http.ResponseWriter, r *http.Request) {

	user, err := providerLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	numberPlateVal := r.FormValue("numberplate")
	if numberPlateVal == "" {
		fmt.Println("Error")
		http.Redirect(w, r, "/providerhome", http.StatusFound)
		return
	}

	// Checking if this vehicle has been made available to be rented out by the provider.
	// If yes, then can't delete this directly
	vehiclesMadeAvailable := user.AvailableVehicleSlice
	for _, val := range vehiclesMadeAvailable {
		if val.NumberPlate == numberPlateVal {
			tpl.ExecuteTemplate(w, "vehicledeletion.html", "Can't delete this vehicle because it has been made available for renting. Kindly delete this vehicle from available vehicles first.")
			return
		}
	}

	vehicleSlice := user.Vehicles
	var newVehicleSlice []model.Vehicle

	// Removing the deleted vehicle
	for _, val := range vehicleSlice {
		if val.NumberPlate == numberPlateVal {
			continue
		}
		newVehicleSlice = append(newVehicleSlice, val)
	}

	// Updating the provider's info
	newUserInfo := user
	newUserInfo.Vehicles = newVehicleSlice
	Uc.session.DB("rentaride").C("provider").Update(user, newUserInfo)

	// Removing the number plate from takennumberplate collection
	Uc.session.DB("rentaride").C("takennumberplates").Remove(bson.M{"numberplate": numberPlateVal})

	http.Redirect(w, r, "/providerhome", http.StatusFound)
	return
}

// Renting out a vehicle. Making the vehicle available
func RentOut(w http.ResponseWriter, r *http.Request) {
	user, err := providerLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodGet {
		numberPlateVal := r.FormValue("numberplate")

		reqdVehicle := model.Vehicle{}
		for _, val := range user.Vehicles {
			if numberPlateVal == val.NumberPlate {
				reqdVehicle = val
				break
			}
		}
		if reqdVehicle.NumberPlate == "" {
			http.Error(w, "You can't visit this page.", 404)
			return
		}

		data := struct {
			Reqd model.Vehicle
			Info string
		}{
			reqdVehicle,
			"",
		}

		// Display issues if any. Redirected from /rentoutprocess
		issue := r.FormValue("info")
		if issue != "" {
			data.Info = issue
			tpl.ExecuteTemplate(w, "rentout.html", data)
			return
		}

		tpl.ExecuteTemplate(w, "rentout.html", data)
		return
	}
}

// Rent out helper function
func RentOutProcess(w http.ResponseWriter, r *http.Request) {
	user, err := providerLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodPost {
		numberPlateVal := r.FormValue("numberplate")

		var issue string

		// Checking if the vehicle has already been made available or not
		for _, val := range user.AvailableVehicleSlice {
			if val.NumberPlate == numberPlateVal {
				issue = "Vehicle has already been made available. You can't make a vehicle available more than once."
				http.Redirect(w, r, "/rentout?numberplate="+numberPlateVal+"&info="+issue, http.StatusFound)
				return
			}
		}

		reqdVehicle := model.Vehicle{}
		for _, val := range user.Vehicles {
			if numberPlateVal == val.NumberPlate {
				reqdVehicle = val
				break
			}
		}

		if reqdVehicle.NumberPlate == "" {
			http.Error(w, "You can't visit this page.", 404)
			return
		}

		startTimeString := r.FormValue("start")
		endTimeString := r.FormValue("end")
		askingPrice := r.FormValue("price")

		curTime := time.Now()
		startTime := convertingTime(startTimeString)
		endTime := convertingTime(endTimeString)

		// Checking is start time and end time are valid
		if curTime.After(startTime) {
			issue = "Start time should be greater than the current time."
		} else if startTime.After(endTime) {
			issue = "End time should be greater than the start time."
		}
		if duration := endTime.Sub(startTime); duration.Hours() > 8760 {
			issue = "Vehicle can not be rented out for more than a year."
		}
		if val, _ := strconv.Atoi(askingPrice); val <= 0 {
			issue = "Asking Price invalid."
		}

		if issue != "" {
			http.Redirect(w, r, "/rentout?numberplate="+numberPlateVal+"&info="+issue, http.StatusFound)
			return
		}

		id := bson.NewObjectId()
		dataAvailableVehicles := model.AvailableVehicles{
			Id:               id,
			NumberPlate:      reqdVehicle.NumberPlate,
			ProviderUsername: user.Username,
			StartTime:        startTime,
			EndTime:          endTime,
			AskingPrice:      askingPrice,
			VehicleInfo:      reqdVehicle,
		}

		Uc.session.DB("rentaride").C("availablevehicles").Insert(dataAvailableVehicles) // Inserting to db

		// Now update the current provider's info. Update the provider's available vehicles slice
		dataAvailableVehicleProvider := model.AvailableVehicleProvider{
			Id:          id,
			NumberPlate: reqdVehicle.NumberPlate,
			StartTime:   startTime,
			EndTime:     endTime,
			AskingPrice: askingPrice,
		}

		newUserInfo := user

		availableVehicleSlice := user.AvailableVehicleSlice
		availableVehicleSlice = append(availableVehicleSlice, dataAvailableVehicleProvider)
		newUserInfo.AvailableVehicleSlice = availableVehicleSlice

		Uc.session.DB("rentaride").C("provider").Update(user, newUserInfo)

		http.Redirect(w, r, "/providerhome", http.StatusFound)
	}
}

// Find a vehicle
func FindAVehicle(w http.ResponseWriter, r *http.Request) {
	_, err := riderLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodGet {
		data := struct {
			Info         string
			StartTimeStr string
			EndTimeStr   string
			AvlVehicles  []model.AvailableVehicles
		}{}
		tpl.ExecuteTemplate(w, "findavehicle.html", data)
		return
	}

	if r.Method == http.MethodPost {
		// After taking the starting time and ending time as input

		startTimeString := r.FormValue("start")
		endTimeString := r.FormValue("end")

		curTime := time.Now()
		startTime := convertingTime(startTimeString)
		endTime := convertingTime(endTimeString)

		var issue string

		if curTime.After(startTime) {
			issue = "Start time should be greater than the current time."
		} else if startTime.After(endTime) {
			issue = "End time should be greater than the start time."
		}
		if duration := endTime.Sub(startTime); duration.Hours() > 8760 {
			issue = "Vehicle can not be rented for more than a year."
		}

		data := struct {
			Info         string
			StartTimeStr string
			EndTimeStr   string
			AvlVehicles  []model.AvailableVehicles
			StartTimeVal time.Time
			EndTimeVal   time.Time
		}{}

		if issue != "" {
			data.Info = issue
			tpl.ExecuteTemplate(w, "findavehicle.html", data)
			return
		}

		data.StartTimeStr = startTimeString
		data.EndTimeStr = endTimeString

		data.StartTimeVal = startTime
		data.EndTimeVal = endTime

		// All available vehicles
		var availableVehiclesFromDB []model.AvailableVehicles

		Uc.session.DB("rentaride").C("availablevehicles").Find(bson.M{"starttime": bson.M{"$lte": startTime}, "endtime": bson.M{"$gte": endTime}}).All(&availableVehiclesFromDB)

		// Vehicles available at the time we provided
		availableForRent := make([]model.AvailableVehicles, 0)

		for _, val := range availableVehiclesFromDB {
			tempRentedTime := val.RentedTime
			tempFlag := 0
			for _, rentedVal := range tempRentedTime {
				if tempFlag == 1 {
					break
				}
				if rentedVal.EndTime.Before(startTime) && rentedVal.EndTime.Before(endTime) {
					tempFlag = 0
				} else if rentedVal.StartTime.After(startTime) && rentedVal.StartTime.After(endTime) {
					tempFlag = 0
				} else {
					tempFlag = 1
					break
				}
			}
			if tempFlag == 0 {
				availableForRent = append(availableForRent, val)
			}
		}

		for i, val := range availableForRent {
			// Change Asking price to asking price + 10% for the Rider
			tempPrice, _ := strconv.Atoi(val.AskingPrice)
			tempPrice = (tempPrice + int(tempPrice/10)) * gettingHours(startTime, endTime) // Total time from start time to end time
			availableForRent[i].AskingPrice = strconv.Itoa(tempPrice)

			// Convert images to encoded format
			encodedImages := make([]string, 0)
			for _, v := range val.VehicleInfo.ImageNames {
				encoded := GetImage(v)
				encodedImages = append(encodedImages, encoded)
			}
			availableForRent[i].VehicleInfo.ImageNames = encodedImages
		}

		data.AvlVehicles = availableForRent
		tpl.ExecuteTemplate(w, "findavehicle.html", data)

	}
}

// Rider booking a vehicle
func BookAVehicle(w http.ResponseWriter, r *http.Request) {
	_, err := riderLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodGet {
		numberPlate := r.FormValue("numberplate")
		startTimeString := r.FormValue("starttime")
		endTimeString := r.FormValue("endtime")

		startTime := convertingTime(startTimeString)
		endTime := convertingTime(endTimeString)

		ReqdVehicle := model.AvailableVehicles{}

		Uc.session.DB("rentaride").C("availablevehicles").Find(bson.M{"numberplate": numberPlate}).One(&ReqdVehicle)

		imageNames := ReqdVehicle.VehicleInfo.ImageNames // Image UUIDs of the vehicle

		var encodedImages []string // To store the encoded Image URLs

		for _, v := range imageNames {
			encoded := GetImage(v)
			encodedImages = append(encodedImages, encoded)
		}

		ReqdVehicle.VehicleInfo.ImageNames = encodedImages
		tempPrice, _ := strconv.Atoi(ReqdVehicle.AskingPrice)
		tempPrice = (tempPrice + int(tempPrice/10)) * gettingHours(startTime, endTime)
		ReqdVehicle.AskingPrice = strconv.Itoa(tempPrice)

		// startDateVal, startTimeVal := extractDateAndTime(startTimeString)
		// endDateVal, endTimeVal := extractDateAndTime(endTimeString)
		data := struct {
			AvlVehicle   model.AvailableVehicles
			StartTime    string
			EndTime      string
			StartTimeVal time.Time
			EndTimeVal   time.Time
		}{
			ReqdVehicle,
			startTimeString,
			endTimeString,
			startTime,
			endTime,
		}

		tpl.ExecuteTemplate(w, "bookavehicle.html", data)
		return
	}
}

// Rider confirming their booking
func Confirm(w http.ResponseWriter, r *http.Request) {
	user, err := riderLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodPost {
		numberPlate := r.FormValue("numberplate")
		startTimeString := r.FormValue("starttime")
		endTimeString := r.FormValue("endtime")

		startTime := convertingTime(startTimeString)
		endTime := convertingTime(endTimeString)

		ReqdVehicle := model.AvailableVehicles{}

		// Info of the reqd vehicle from db
		Uc.session.DB("rentaride").C("availablevehicles").Find(bson.M{"numberplate": numberPlate}).One(&ReqdVehicle)

		// Time in which the vehicle has already been rented
		// Checking if the vehicle has been booked by someone else during our process
		tempRentedTime := ReqdVehicle.RentedTime
		tempFlag := 0
		for _, rentedVal := range tempRentedTime {
			if tempFlag == 1 {
				break
			}
			if rentedVal.EndTime.Before(startTime) && rentedVal.EndTime.Before(endTime) {
				tempFlag = 0
			} else if rentedVal.StartTime.After(startTime) && rentedVal.StartTime.After(endTime) {
				tempFlag = 0
			} else {
				tempFlag = 1
				break
			}
		}
		if tempFlag == 1 {
			data := struct {
				Info string
			}{}
			data.Info = "Too late, Vehicle has been booked by someone else."
			tpl.ExecuteTemplate(w, "confirm.html", data)
			return
		}

		// Adding the time we'll be renting the vehicle in the vehicle's info
		newReqdVehicle := ReqdVehicle
		newReqdVehicle.RentedTime = append(newReqdVehicle.RentedTime, model.StartEndTime{
			StartTime: startTime,
			EndTime:   endTime,
		})

		Uc.session.DB("rentaride").C("availablevehicles").Update(ReqdVehicle, newReqdVehicle)

		// Vehicle's data for storing in rider's and provider's profile
		VehicleData := model.RentedVehicleInfo{
			Id:               bson.NewObjectId(),
			NumberPlate:      ReqdVehicle.NumberPlate,
			ProviderUsername: ReqdVehicle.ProviderUsername,
			RiderUsername:    user.Username,
			StartTime:        startTime,
			EndTime:          endTime,
			AskingPrice:      ReqdVehicle.AskingPrice,
		}

		// Changing asking price to price * time
		tempPrice, _ := strconv.Atoi(ReqdVehicle.AskingPrice)
		tempPrice = tempPrice * gettingHours(startTime, endTime)
		VehicleData.AskingPrice = strconv.Itoa(tempPrice)

		// Updating provider's info
		providerInfo := model.Provider{}

		Uc.session.DB("rentaride").C("provider").Find(bson.M{"username": ReqdVehicle.ProviderUsername}).One(&providerInfo)

		newProviderInfo := providerInfo
		newProviderInfo.Bookings = append(newProviderInfo.Bookings, VehicleData)

		// Provider can redeem this amount later
		newProviderInfo.RedeemInfo = append(newProviderInfo.RedeemInfo, model.Redeem{
			NumberPlate: ReqdVehicle.NumberPlate,
			StartTime:   startTime,
			EndTime:     endTime,
			Amount:      VehicleData.AskingPrice,
			Redeemed:    "0",
			Query:       "1",
		})

		Uc.session.DB("rentaride").C("provider").Update(providerInfo, newProviderInfo)

		// Adding the payment made to the provider in the transactions collection
		transactionInfo := model.Transactions{
			Id:               bson.NewObjectId(),
			NumberPlate:      ReqdVehicle.NumberPlate,
			ProviderUsername: ReqdVehicle.ProviderUsername,
			RiderUsername:    user.Username,
			StartTime:        startTime,
			EndTime:          endTime,
			Amount:           VehicleData.AskingPrice,
			Query:            "2",
		}

		Uc.session.DB("rentaride").C("transactions").Insert(transactionInfo)

		// Updating rider's info
		newRider := user

		// Changinf price to (price + 10%) * time
		tempPrice, _ = strconv.Atoi(ReqdVehicle.AskingPrice)
		tempPrice = (tempPrice + int(tempPrice/10)) * gettingHours(startTime, endTime)
		VehicleData.AskingPrice = strconv.Itoa(tempPrice)

		newRider.Bookings = append(newRider.Bookings, VehicleData)

		Uc.session.DB("rentaride").C("rider").Update(user, newRider)

		// Adding the transaction info of money paid by rider in the db
		transactionInfo2 := model.Transactions{
			Id:               bson.NewObjectId(),
			NumberPlate:      ReqdVehicle.NumberPlate,
			ProviderUsername: ReqdVehicle.ProviderUsername,
			RiderUsername:    user.Username,
			StartTime:        startTime,
			EndTime:          endTime,
			Amount:           VehicleData.AskingPrice,
			Query:            "1",
		}

		Uc.session.DB("rentaride").C("transactions").Insert(transactionInfo2)

		http.Redirect(w, r, "/riderhome", http.StatusFound)
	}
}

// Rider's bookings page
func RiderBookings(w http.ResponseWriter, r *http.Request) {
	user, err := riderLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	// Rider's bookings
	bookingData := user.Bookings

	futureBookings := make([]model.RentedVehicleInfo, 0)
	pastBookings := make([]model.RentedVehicleInfo, 0)

	curTime := time.Now()

	// Dividing the bookings into past and future bookings based on their start time
	for _, val := range bookingData {
		if val.StartTime.After(curTime) {
			futureBookings = append(futureBookings, val)
		} else {
			pastBookings = append(pastBookings, val)
		}
	}

	// Sorting on the basis of start time
	sort.Slice(pastBookings, func(i, j int) bool {
		if pastBookings[i].StartTime.Before(pastBookings[j].StartTime) {
			return true
		}
		return false
	})

	sort.Slice(futureBookings, func(i, j int) bool {
		if futureBookings[i].StartTime.Before(futureBookings[j].StartTime) {
			return true
		}
		return false
	})

	data := struct {
		FutureBookings []model.RentedVehicleInfo
		PastBookings   []model.RentedVehicleInfo
	}{
		futureBookings,
		pastBookings,
	}

	tpl.ExecuteTemplate(w, "riderbookings.html", data)
}

// If the rider deletes, the rider is paid back the 10% extra he paid. Provider is unaffected by this
func RiderBookingDelete(w http.ResponseWriter, r *http.Request) {
	user, err := riderLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodGet {

		ReqdVehicle := model.RentedVehicleInfo{}

		numberPlate := r.FormValue("numberplate")
		startTimeString := r.FormValue("starttime")
		endTimeString := r.FormValue("endtime")

		curTime := time.Now()
		startTime := convertingTime(startTimeString)
		endTime := convertingTime(endTimeString)

		if curTime.After(startTime) {
			http.Redirect(w, r, "/riderhome", http.StatusSeeOther)
			return
		}

		// Finding the booking to be deleted from the Rider's booking data
		bookingData := user.Bookings
		for _, val := range bookingData {
			if val.NumberPlate == numberPlate && val.StartTime.Equal(startTime) && val.EndTime.Equal(endTime) {
				ReqdVehicle = val
				break
			}
		}

		// Changing the ReqdVehicle's price according to the rider's payment
		tempPrice, _ := strconv.Atoi(ReqdVehicle.AskingPrice)
		tempPrice = (tempPrice + int(tempPrice/10)) * gettingHours(startTime, endTime)
		ReqdVehicle.AskingPrice = strconv.Itoa(tempPrice)

		tpl.ExecuteTemplate(w, "riderbookingdelete.html", ReqdVehicle)
	}

	if r.Method == http.MethodPost {

		ReqdVehicle := model.RentedVehicleInfo{}

		numberPlate := r.FormValue("numberplate")
		startTimeString := r.FormValue("starttime")
		endTimeString := r.FormValue("endtime")

		curTime := time.Now()
		startTime := convertingTime(startTimeString)
		endTime := convertingTime(endTimeString)

		if curTime.After(startTime) {
			http.Redirect(w, r, "/riderhome", http.StatusSeeOther)
			return
		}

		// Getting the vehicle info from booking data
		bookingData := user.Bookings
		for _, val := range bookingData {
			if val.NumberPlate == numberPlate && val.StartTime.Equal(startTime) && val.EndTime.Equal(endTime) {
				ReqdVehicle = val
				break
			}
		}

		// Updating the vehicle in availablevehicles by removing the time for which we're deleting the entry
		tempAvlVehicle := model.AvailableVehicles{}
		Uc.session.DB("rentaride").C("availablevehicles").Find(bson.M{"numberplate": numberPlate}).One(&tempAvlVehicle)

		newAvlVehicle := tempAvlVehicle
		newRentedTime := make([]model.StartEndTime, 0)
		for _, val := range tempAvlVehicle.RentedTime {
			if val.StartTime.Equal(startTime) && val.EndTime.Equal(endTime) {
				continue
			} else {
				newRentedTime = append(newRentedTime, val)
			}

		}
		newAvlVehicle.RentedTime = newRentedTime
		Uc.session.DB("rentaride").C("availablevehicles").Update(tempAvlVehicle, newAvlVehicle)

		// Updating provider's info
		tempProvider := model.Provider{}
		Uc.session.DB("rentaride").C("provider").Find(bson.M{"username": ReqdVehicle.ProviderUsername}).One(&tempProvider)

		newProvider := tempProvider
		newBookings := make([]model.RentedVehicleInfo, 0)

		for _, val := range tempProvider.Bookings {
			if val.StartTime.Equal(startTime) && val.EndTime.Equal(endTime) && val.NumberPlate == numberPlate {
				continue
			} else {
				newBookings = append(newBookings, val)
			}

		}
		newProvider.Bookings = newBookings
		Uc.session.DB("rentaride").C("provider").Update(tempProvider, newProvider)

		// Update rider's info
		newRider := user
		newBookingsRider := make([]model.RentedVehicleInfo, 0)

		for _, val := range user.Bookings {
			if val.StartTime.Equal(startTime) && val.EndTime.Equal(endTime) && val.NumberPlate == numberPlate {
				continue
			} else {
				newBookingsRider = append(newBookingsRider, val)
			}

		}
		newRider.Bookings = newBookingsRider

		// Amount we pay back to the rider
		payBackToRider, _ := strconv.Atoi(tempAvlVehicle.AskingPrice)
		payBackToRider = int(payBackToRider/10) * gettingHours(startTime, endTime)

		newRider.RedeemInfo = append(newRider.RedeemInfo, model.Redeem{
			NumberPlate: ReqdVehicle.NumberPlate,
			StartTime:   startTime,
			EndTime:     endTime,
			Amount:      strconv.Itoa(payBackToRider),
			Redeemed:    "0",
			Query:       "1",
		})

		Uc.session.DB("rentaride").C("rider").Update(user, newRider)

		// Adding the money paid back to rider in the transaction collection
		transactionInfo := model.Transactions{
			Id:               bson.NewObjectId(),
			NumberPlate:      ReqdVehicle.NumberPlate,
			ProviderUsername: ReqdVehicle.ProviderUsername,
			RiderUsername:    user.Username,
			StartTime:        startTime,
			EndTime:          endTime,
			Amount:           strconv.Itoa(payBackToRider),
			Query:            "3",
		}

		Uc.session.DB("rentaride").C("transactions").Insert(transactionInfo)

		http.Redirect(w, r, "/riderbookings", http.StatusFound)
	}
}

// Same as rider bookings
func ProviderBookings(w http.ResponseWriter, r *http.Request) {
	user, err := providerLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	bookingData := user.Bookings

	futureBookings := make([]model.RentedVehicleInfo, 0)
	pastBookings := make([]model.RentedVehicleInfo, 0)

	curTime := time.Now()

	for _, val := range bookingData {
		if val.StartTime.After(curTime) {
			futureBookings = append(futureBookings, val)
		} else {
			pastBookings = append(pastBookings, val)
		}
	}

	sort.Slice(pastBookings, func(i, j int) bool {
		if pastBookings[i].StartTime.Before(pastBookings[j].StartTime) {
			return true
		}
		return false
	})

	sort.Slice(futureBookings, func(i, j int) bool {
		if futureBookings[i].StartTime.Before(futureBookings[j].StartTime) {
			return true
		}
		return false
	})

	data := struct {
		FutureBookings []model.RentedVehicleInfo
		PastBookings   []model.RentedVehicleInfo
	}{
		futureBookings,
		pastBookings,
	}

	tpl.ExecuteTemplate(w, "providerbookings.html", data)
}

// Provider's available vehicles
func ProviderAvailableVehicles(w http.ResponseWriter, r *http.Request) {
	user, err := providerLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	AvlVehicles := user.AvailableVehicleSlice
	tpl.ExecuteTemplate(w, "provideravailablevehicles.html", AvlVehicles)
}

// Provider deleting an available vehicle
func DeleteAvailableVehicle(w http.ResponseWriter, r *http.Request) {
	user, err := providerLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodGet {
		ReqdVehicle := model.RentedVehicleInfo{}

		numberPlate := r.FormValue("numberplate")

		Uc.session.DB("rentaride").C("availablevehicles").Find(bson.M{"numberplate": numberPlate}).One(&ReqdVehicle)

		tpl.ExecuteTemplate(w, "deleteavailablevehicle.html", ReqdVehicle)
		return
	}

	if r.Method == http.MethodPost {

		numberPlate := r.FormValue("numberplate")

		curTime := time.Now()

		// Delete the vehicle's info from availablevehicles collection
		Uc.session.DB("rentaride").C("availablevehicles").Remove(bson.M{"numberplate": numberPlate})

		// Updating provider's info
		newProvider := user

		newAvlVehiclesSlice := make([]model.AvailableVehicleProvider, 0) // New slice for available vehicles after deleting the current vehicle
		for _, val := range user.AvailableVehicleSlice {
			if val.NumberPlate == numberPlate {
				continue
			} else {
				newAvlVehiclesSlice = append(newAvlVehiclesSlice, val)
			}
		}

		newProvider.AvailableVehicleSlice = newAvlVehiclesSlice // Setting the avl vehicle slice to the new avl vehicle slice

		ridersWhoBookedThisVehicle := make([]string, 0)           // For finding the riders we need to deal with
		providerNewBookings := make([]model.RentedVehicleInfo, 0) // New provider bookings after deleting this vehicle's bookings
		providerNewRedeem := make([]model.Redeem, 0)              // New provider redeem info

		for _, val := range user.Bookings {
			if val.NumberPlate == numberPlate && val.StartTime.After(curTime) {
				ridersWhoBookedThisVehicle = append(ridersWhoBookedThisVehicle, val.RiderUsername)

			} else {
				providerNewBookings = append(providerNewBookings, val)
			}
		}

		for _, val := range user.RedeemInfo {
			if val.NumberPlate == numberPlate && val.StartTime.After(curTime) {
				continue
			} else {
				providerNewRedeem = append(providerNewRedeem, val)
			}
		}

		newProvider.Bookings = providerNewBookings // New boookings
		newProvider.RedeemInfo = providerNewRedeem // New redeem info

		Uc.session.DB("rentaride").C("provider").Update(user, newProvider) // Updating the provider

		for _, val := range ridersWhoBookedThisVehicle {

			// Firstly extract the rider's info from the username provided
			tempRider := model.Rider{}
			Uc.session.DB("rentaride").C("rider").Find(bson.M{"username": val}).One(&tempRider)

			newRider := tempRider

			newBookings := make([]model.RentedVehicleInfo, 0) // To store new bookings
			newRedeem := tempRider.RedeemInfo                 // To store new redeeminfo

			for _, v := range tempRider.Bookings {
				if v.NumberPlate == numberPlate && v.StartTime.After(curTime) {
					newRedeem = append(newRedeem, model.Redeem{
						NumberPlate: numberPlate,
						StartTime:   v.StartTime,
						EndTime:     v.EndTime,
						Amount:      v.AskingPrice,
						Redeemed:    "0",
						Query:       "2",
					})

					// Adding the payment made to the provider in the transactions collection
					transactionInfo := model.Transactions{
						Id:               bson.NewObjectId(),
						NumberPlate:      numberPlate,
						ProviderUsername: user.Username,
						RiderUsername:    val,
						StartTime:        v.StartTime,
						EndTime:          v.EndTime,
						Amount:           v.AskingPrice,
						Query:            "4",
					}

					Uc.session.DB("rentaride").C("transactions").Insert(transactionInfo)

				} else {
					newBookings = append(newBookings, v)
				}
			}

			newRider.Bookings = newBookings // Updating bookings
			newRider.RedeemInfo = newRedeem // Updating redeeminfo

			Uc.session.DB("rentaride").C("rider").Update(tempRider, newRider)
		}
		http.Redirect(w, r, "/provideravailablevehicles", http.StatusFound)
		return

	}
}

// Rider redeem page
func RiderRedeem(w http.ResponseWriter, r *http.Request) {
	user, err := riderLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	sort.Slice(user.RedeemInfo, func(i, j int) bool {
		if user.RedeemInfo[i].StartTime.After(user.RedeemInfo[j].StartTime) {
			return true
		}
		return false
	})

	tpl.ExecuteTemplate(w, "riderredeem.html", user)
}

// Rider redeem helper function. Can add payment gateway here
func RiderRedeemProcess(w http.ResponseWriter, r *http.Request) {
	user, err := riderLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodPost {

		numberPlate := r.FormValue("numberplate")
		startTimeString := r.FormValue("starttime")
		endTimeString := r.FormValue("endtime")

		startTime := convertingTime(startTimeString)
		endTime := convertingTime(endTimeString)

		newRider := user
		newRedeemInfo := make([]model.Redeem, 0)

		// Change the value of Redeemed from 0 to 1
		for _, val := range user.RedeemInfo {
			if val.NumberPlate == numberPlate && val.StartTime.Equal(startTime) && val.EndTime.Equal(endTime) {
				val.Redeemed = "1"
			}
			newRedeemInfo = append(newRedeemInfo, val)
		}

		newRider.RedeemInfo = newRedeemInfo

		Uc.session.DB("rentaride").C("rider").Update(user, newRider)

		http.Redirect(w, r, "/riderredeem", http.StatusFound)
	}
}

// Provider redeem page
func ProviderRedeem(w http.ResponseWriter, r *http.Request) {
	user, err := providerLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	curTime := time.Now()
	RedeemInfoSlice := make([]model.Redeem, 0)

	for _, val := range user.RedeemInfo {
		if val.EndTime.Before(curTime) {
			RedeemInfoSlice = append(RedeemInfoSlice, val)
		}
	}

	sort.Slice(RedeemInfoSlice, func(i, j int) bool {
		if RedeemInfoSlice[i].StartTime.After(RedeemInfoSlice[j].StartTime) {
			return true
		}
		return false
	})

	tpl.ExecuteTemplate(w, "providerredeem.html", RedeemInfoSlice)
}

// Provider redeem helper function. Can add payment gateway here
func ProviderRedeemProcess(w http.ResponseWriter, r *http.Request) {
	user, err := providerLoggedInOrNot(r)
	if err != nil {
		http.Error(w, "You can't visit this page.", 404)
		return
	}

	if r.Method == http.MethodPost {

		numberPlate := r.FormValue("numberplate")
		startTimeString := r.FormValue("starttime")
		endTimeString := r.FormValue("endtime")

		startTime := convertingTime(startTimeString)
		endTime := convertingTime(endTimeString)

		newProvider := user
		newRedeemInfo := make([]model.Redeem, 0)
		for _, val := range user.RedeemInfo {
			if val.NumberPlate == numberPlate && val.StartTime.Equal(startTime) && val.EndTime.Equal(endTime) {
				val.Redeemed = "1"
			}
			newRedeemInfo = append(newRedeemInfo, val)
		}

		newProvider.RedeemInfo = newRedeemInfo

		Uc.session.DB("rentaride").C("provider").Update(user, newProvider)

		http.Redirect(w, r, "/providerredeem", http.StatusFound)
	}
}
