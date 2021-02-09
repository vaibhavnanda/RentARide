function deleteVehicle(obj) {
    var val = JSON.parse(obj);
    var numberplate = val.numberplate
    var ask = window.confirm("Are you sure you want to delete this vehicle?");
    if (ask) {
        
        window.location.href = "/vehicledeletion?numberplate=" + numberplate;

    }  
}