# Spring Security
formLogin()
This has several methods that we can use to configure the behavior of the form login:
* loginProcessingUrl() – the url to submit the username and password to
* successHandler() – after a successful login
* failureHandler() – after an unsuccessful login
* deleteCookies() - delete cookie after an logout
* invalidSessionStrategy() - session timeout or invalid
* tokenValiditySeconds() - Allows specifying how long (in seconds) a token is valid for
* rememberMeCookieName() - The name of cookie which store the token for remember me authentication.

# Run Server
<p>Run the application over the server and see it produces the following output to the browser.</p>
<p align="center">Click on link, a login form is rendered that will use for form-based authentication.</p>
<p align="center"><img src="https://user-images.githubusercontent.com/16053126/93633862-4ef36100-f9f8-11ea-8aeb-8bdd9285f244.PNG" width=250/></p>

<p align="center">After validating credentials it authenticate the user and add cookie(rememberMe).</p>

![remember](https://user-images.githubusercontent.com/16053126/93633959-76e2c480-f9f8-11ea-9961-87d93d6e461b.PNG)

