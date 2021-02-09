package main

import (
	"RentARide/controller"
	"net/http"
)

func main() {

	staticFile := http.FileServer(http.Dir("./assets/"))
	http.Handle("/assets/", http.StripPrefix("/assets/", staticFile))

	controller.ScheduleUpdates() // To delete outdated values from availablevehicle collection every 10 minutes

	http.Handle("/favicon.ico", http.NotFoundHandler())

	http.HandleFunc("/", controller.Index)
	http.HandleFunc("/riderlogin", controller.RiderLogin)
	http.HandleFunc("/ridersignup", controller.RiderSignup)
	http.HandleFunc("/riderhome", controller.RiderHome)
	http.HandleFunc("/riderlogout", controller.RiderLogout)
	http.HandleFunc("/findavehicle", controller.FindAVehicle)
	http.HandleFunc("/bookavehicle", controller.BookAVehicle)
	http.HandleFunc("/confirm", controller.Confirm)
	http.HandleFunc("/riderbookings", controller.RiderBookings)
	http.HandleFunc("/riderbookingdelete", controller.RiderBookingDelete)
	http.HandleFunc("/riderredeem", controller.RiderRedeem)
	http.HandleFunc("/riderredeemprocess", controller.RiderRedeemProcess)

	http.HandleFunc("/providerlogin", controller.ProviderLogin)
	http.HandleFunc("/providersignup", controller.ProviderSignup)
	http.HandleFunc("/providerhome", controller.ProviderHome)
	http.HandleFunc("/providerlogout", controller.ProviderLogout)
	http.HandleFunc("/addvehicle", controller.AddVehicle)
	http.HandleFunc("/vehicleinfo", controller.VehicleInfo)
	http.HandleFunc("/vehicledeletion", controller.VehicleDeletion)
	http.HandleFunc("/rentout", controller.RentOut)
	http.HandleFunc("/rentoutprocess", controller.RentOutProcess)
	http.HandleFunc("/providerbookings", controller.ProviderBookings)
	http.HandleFunc("/provideravailablevehicles", controller.ProviderAvailableVehicles)
	http.HandleFunc("/deleteavailablevehicle", controller.DeleteAvailableVehicle)
	http.HandleFunc("/providerredeem", controller.ProviderRedeem)
	http.HandleFunc("/providerredeemprocess", controller.ProviderRedeemProcess)

	http.ListenAndServe(":8080", nil)
}
