package model

import (
	"time"

	"gopkg.in/mgo.v2/bson"
)

type Vehicle struct {
	Id               bson.ObjectId `json:"id" bson:"_id"`
	NumberPlate      string        `json:"numberplate" bson:"numberplate,omitempty"`
	Wheels           string        `json:"wheels" bson:"wheels,omitempty"`
	Name             string        `json:"name" bson:"name,omitempty"`
	ProviderUsername string        `json:"providerusername" bson:"providerusername,omitempty"`
	Location         string        `json:"location" bson:"location,omitempty"`
	ImageNames       []string      `json:"imagenames" bson:"imagenames"`
}

type RentedVehicleInfo struct {
	Id               bson.ObjectId `json:"id" bson:"_id"`
	NumberPlate      string        `json:"numberplate" bson:"numberplate,omitempty"`
	ProviderUsername string        `json:"providerusername" bson:"providerusername,omitempty"`
	RiderUsername    string        `json:"riderusername" bson:"riderusername,omitempty"`
	StartTime        time.Time     `json:"starttime" bson:"starttime,omitempty"`
	EndTime          time.Time     `json:"endtime" bson:"endtime,omitempty"`
	AskingPrice      string        `json:"askingprice" bson:"askingprice,omitempty`
}

type StartEndTime struct {
	StartTime time.Time `json:"starttime" bson:"starttime,omitempty"`
	EndTime   time.Time `json:"endtime" bson:"endtime,omitempty"`
}

type Redeem struct {
	NumberPlate string    `json:"numberplate" bson:"numberplate,omitempty"`
	StartTime   time.Time `json:"starttime" bson:"starttime,omitempty"`
	EndTime     time.Time `json:"endtime" bson:"endtime,omitempty"`
	Amount      string    `json:"amount" bson:"amount,omitempty"`
	Redeemed    string    `json:"redeemed" bson:"redeemed,omitempty"`
	Query       string    `json:"query" bson:"query,omitempty"`
}

type AvailableVehicles struct {
	Id               bson.ObjectId  `json:"id" bson:"_id"`
	NumberPlate      string         `json:"numberplate" bson:"numberplate,omitempty"`
	ProviderUsername string         `json:"providerusername" bson:"providerusername,omitempty"`
	StartTime        time.Time      `json:"starttime" bson:"starttime,omitempty"`
	EndTime          time.Time      `json:"endtime" bson:"endtime,omitempty"`
	AskingPrice      string         `json:"askingprice" bson:"askingprice,omitempty`
	RentedTime       []StartEndTime `json:"rentedtime" bson:"rentedtime"`
	VehicleInfo      Vehicle        `json:"vehicleinfo" bson:"vehicleinfo,omitempty"`
}

type AvailableVehicleProvider struct {
	Id          bson.ObjectId `json:"id" bson:"_id"`
	NumberPlate string        `json:"numberplate" bson:"numberplate,omitempty"`
	StartTime   time.Time     `json:"starttime" bson:"starttime,omitempty"`
	EndTime     time.Time     `json:"endtime" bson:"endtime,omitempty"`
	AskingPrice string        `json:"askingprice" bson:"askingprice,omitempty`
}

type Rider struct {
	Id         bson.ObjectId       `json:"id" bson:"_id"`
	Username   string              `json:"username" bson:"username,omitempty"`
	Password   []byte              `json:"password" bson:"password,omitempty"`
	Name       string              `json:"name" bson:"name,omitempty"`
	Address    string              `json:"address" bson:"address,omitempty"`
	Dl         string              `json:"dl" bson:"dl,omitempty"`
	Phone      string              `json:"phone" bson:"phone,omitempty"`
	Bookings   []RentedVehicleInfo `json:"bookings" bson:"bookings"`
	RedeemInfo []Redeem            `json:"redeeminfo" bson:"redeeminfo"`
}

type Provider struct {
	Id                    bson.ObjectId              `json:"id" bson:"_id"`
	Username              string                     `json:"username" bson:"username,omitempty"`
	Password              []byte                     `json:"password" bson:"password,omitempty"`
	Name                  string                     `json:"name" bson:"name,omitempty"`
	Address               string                     `json:"address" bson:"address,omitempty"`
	Adhaar                string                     `json:"adhaar" bson:"adhaar,omitempty"`
	Phone                 string                     `json:"phone" bson:"phone,omitempty"`
	Vehicles              []Vehicle                  `json:"vehicles" bson:"vehicles"`
	AvailableVehicleSlice []AvailableVehicleProvider `json:"availablevehicleslice" bson:"availablevehicleslice"`
	Bookings              []RentedVehicleInfo        `json:"bookings" bson:"bookings"`
	RedeemInfo            []Redeem                   `json:"redeeminfo" bson:"redeeminfo"`
}

type Rsession struct {
	Id       bson.ObjectId `json:"id" bson:"_id"`
	Sid      string        `json:"sid" bson:"sid,omitempty"`
	Username string        `json:"username" bson:"username,omitempty"`
}

type Psession struct {
	Id       bson.ObjectId `json:"id" bson:"_id"`
	Sid      string        `json:"sid" bson:"sid,omitempty"`
	Username string        `json:"username" bson:"username,omitempty"`
}

type TakenNumberPlates struct {
	Id          bson.ObjectId `json:"id" bson:"_id"`
	NumberPlate string        `json:"numberplate" bson:"numberplate,omitempty"`
}

type Transactions struct {
	Id               bson.ObjectId `json:"id" bson:"_id"`
	NumberPlate      string        `json:"numberplate" bson:"numberplate,omitempty"`
	ProviderUsername string        `json:"providerusername" bson:"providerusername,omitempty"`
	RiderUsername    string        `json:"riderusername" bson:"riderusername,omitempty"`
	StartTime        time.Time     `json:"starttime" bson:"starttime,omitempty"`
	EndTime          time.Time     `json:"endtime" bson:"endtime,omitempty"`
	Amount           string        `json:"amount" bson:"amount,omitempty"`
	Query            string        `json:"query" bson:"query,omitempty"`
}

type DateAndTimeForTemplate struct {
	StartDateVal string
	StartTimeVal string
	EndDateVal   string
	EndTimeVal   string
}
