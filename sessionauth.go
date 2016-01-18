// Package login is a middleware for Martini that provides a simple way to track account sessions
// in on a website. Please see https://github.com/martini-contrib/sessionauth/blob/master/README.md
// for a more detailed description of the package.
package sessionauth

import (
	"fmt"
	"github.com/go-martini/martini"
	"github.com/martini-contrib/render"
	"github.com/codinl/session"
	"net/http"
	"github.com/codinl/go-logger"
)

// These are the default configuration values for this package. They
// can be set at anytime, probably during the initial setup of Martini.
var (
	// RedirectUrl should be the relative URL for your login route
	RedirectUrl string = "/account/login"

	AdminRedirectUrl string = "/admin/account/login"

	// RedirectParam is the query string parameter that will be set
	// with the page the account was trying to visit before they were
	// intercepted.
	RedirectParam string = "next"
)

const AUTH_UNIQUE_ID string = "AUTH_UNIQUE_ID"

// Account defines all the functions necessary to work with the account's authentication.
// The caller should implement these functions for whatever system of authentication
// they choose to use
type Account interface {
	// Return whether this account is logged in or not
	IsAuthenticated() bool

	IsAdmin() bool

	// Set any flags or extra data that should be available
	Login()

	// Clear any sensitive data out of the account
	Logout()

	// Return the unique identifier of this account object
	UniqueId() interface{}

	// Populate this account object with values
	GetById(id interface{}) (Account, error)
}

// SessionAccount will try to read a unique account ID out of the session. Then it tries
// to populate an anonymous account object from the database based on that ID. If this
// is successful, the valid account is mapped into the context. Otherwise the anonymous
// account is mapped into the contact.
// The newUser() function should provide a valid 0value structure for the caller's
// account type.
func SessionAccount(newAccount func() Account) martini.Handler {
	return func(s session.Store, c martini.Context) {
		userId := s.Get(AUTH_UNIQUE_ID)
		account := newAccount()

		if userId != nil {
			var err error
			account, err = account.GetById(userId)
			logger.Debug("account=", account)
			if err != nil {
				logger.Error(err)
			} else {
				account.Login()
			}
		}

		c.MapTo(account, (*Account)(nil))
	}
}

// AuthenticateSession will mark the session and account object as authenticated. Then
// the Login() account function will be called. This function should be called after
// you have validated a account.
func AuthenticateSession(s session.Store, account Account) error {
	logger.Debug("AuthenticateSession account=", account)
	account.Login()
	return Update(s, account)
}

// Logout will clear out the session and call the Logout() account function.
func Logout(s session.Store, account Account) {
	account.Logout()
	s.Delete(AUTH_UNIQUE_ID)
}

// LoginRequired verifies that the current account is authenticated. Any routes that
// require a login should have this handler placed in the flow. If the account is not
// authenticated, they will be redirected to /login with the "next" get parameter
// set to the attempted URL.
func LoginRequired(r render.Render, account Account, req *http.Request) {
	if account.IsAuthenticated() == false {
		path := fmt.Sprintf("%s?%s=%s", RedirectUrl, RedirectParam, req.URL.Path)
		r.Redirect(path, 302)
	}
}

func AdminRequired(r render.Render, account Account, req *http.Request) {
	if account.IsAuthenticated() == false || account.IsAdmin() == false {
		path := fmt.Sprintf("%s?%s=%s", AdminRedirectUrl, RedirectParam, req.URL.Path)
		r.Redirect(path, 302)
	}
}

// UpdateUser updates the Account object stored in the session. This is useful incase a change
// is made to the account model that needs to persist across requests.
func Update(s session.Store, account Account) error {
	s.Set(AUTH_UNIQUE_ID, account.UniqueId())
	return nil
}
