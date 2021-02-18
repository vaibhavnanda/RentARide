# RentARide

Rent a ride is a web application written in Golang with the usage of Mongo as a backend storage.
This app serves the function of a rental vehicle marketplace.
Users can rent out their vehicles to earn some money. The rented out vehicles can be rented by the users who need a vehicle for some time.

A user can sign in either as a 'Rider' or a 'Provider'.

# Provider

As a provider, you can add your vehicle on the portal and provide the details of the vehicle which would be available to the users afterwards.
Now you have an option of making this vehicle available to be rented by others. You can make a vehicle available by specifying the start time and the end time and an asking price per hour.
You can view the bookings made by the customers from the Bookings page.
You can also delete a vehicle if you don't want it associated with your peofile anymore. But first you'll have to make the vehicle unavailable for booking.
If later you feel the need to make your vehicle unavailable, you can do that as well. The vehicle will become unavailable after the current booking (if any) of the vehicle ends. You won't be charged any amount for making the vehicle unavailable.
You can redeem the money paid to you by the customers from the Redeem page. You're also paid the amount even if a customer cancels the booking.

# Rider

As a rider you can find a vehicle to be rented. On specifying the start time and the end time, you'll be shown a list of available vehicles for that time. You can select a vehicle of your choice and book it by paying the amount.
You can find your bookings in the Bookings page. You can also cancel a booking from this page. On cancelling you'll be paid a certain amount back.
When a provider makes the vehicle unavailable, you are returned the amount you paid.
Amount paid back to you on cancelling a booking can be redeemed from the Redeem page.

# Sessions
Sessions are maintained with the help of cookies. When logged in as a rider, you can't access the functionalities provided to the Provider and when logged in as a provider, you can't access the functionalities provided to the rider. 

# Handling the money
When a provider specifies the asking price, instead of displaying the amount as it is to the riders, we increment the value by 10% and then display it to the riders. The additional 10% is the profit we make.
When a rider cancels a ride, we only pay them back the additional 10% we charged, and pay the rest to the provider.
When a provider cancels, we pay the rider back the whole amount they paid.

# Database info
Mongo has been used to store the required info.
Images uploaded by a provider are stored using GridFS.
