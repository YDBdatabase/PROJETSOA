function signIn(){
    localStorage.setItem("username","test");
    window.location.reload(false);
}

function signUp(){
    localStorage.setItem("username","test");
}

function logOut(){
    localStorage.clear();
    window.location.href = "./index.html";
    
}