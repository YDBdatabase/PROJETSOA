const dockerIP = "localhost";
const dockerPort = "8000";



/*function signIn(){
    let data = {
        username: document.getElementById('login').value,
        password: document.getElementById('exampleInputPassword1').value,
    }
    
    let req = $.ajax({
        url: 'http://'+dockerIP+':'+dockerPort+'/users/connect',
        type: 'POST',
        contentType: "application/json",
        data: JSON.stringify(data),
        dataType: "json",
        success: [function(){
            localStorage.setItem("username","test");
            window.location.reload(false);
        }],
        error: [function () {
            alert('Error on login');
        }]
    });

    req.then(function(response) {
        console.log(response)
    }, function(xhr) {
        console.error('failed to fetch xhr', xhr)
    })
    
    
}*/

/*function signUp(){
    let data = {
        username: document.getElementById('login').value,
        password: document.getElementById('exampleInputPassword1').value,
    }
    
    let req = $.ajax({
        url: 'http://'+dockerIP+':'+dockerPort+'/users/register',
        type: 'POST',
        contentType: "application/json",
        data: JSON.stringify(data),
        dataType: "json",
        success: [function(){
            alert('User Created');
        }],
        error: [function () {
            console.log(xhr.status);
            alert("Error on user creation");
        }]
    });

    req.then(function(response) {
        console.log(response)
    }, function(xhr) {
        console.error('failed to fetch xhr', xhr)
    })
}*/

function logOut(){
    localStorage.clear();
    window.location.href = "./index.html";
    
}