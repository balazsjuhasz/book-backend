package main

import (
	"net/http"
	"time"

	"github.com/balazsjuhasz/book-backend/internal/data"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func (app *application) routes() http.Handler {
	mux := chi.NewRouter()
	mux.Use(middleware.Recoverer)
	mux.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	mux.Post("/users/login", app.Login)
	mux.Post("/users/logout", app.Logout)

	mux.Route("/admin", func(mux chi.Router) {
		mux.Use(app.AuthTokenMiddleware)

		mux.Post("/users", app.AllUsers)
		mux.Post("/users/save", app.EditUser)
	})

	mux.Get("/users/add", func(w http.ResponseWriter, r *http.Request) {
		u := data.User{
			Email:     "you@there.com",
			FirstName: "You",
			LastName:  "There",
			Password:  "password",
		}

		app.infoLog.Println("Adding user...")

		id, err := app.models.User.Insert(u)
		if err != nil {
			app.errorLog.Println(err)
			app.errorJSON(w, err, http.StatusForbidden)
			return
		}

		app.infoLog.Println("Got back id of", id)
		newUser, _ := app.models.User.GetOne(id)
		app.writeJSON(w, http.StatusOK, newUser)
	})

	mux.Get("/test-generate-token", func(w http.ResponseWriter, r *http.Request) {
		token, err := app.models.User.Token.GenerateToken(1, 60*time.Minute)
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		token.Email = "admin@example.com"
		token.CreatedAt = time.Now()
		token.UpdatedAt = time.Now()

		payload := jsonResponse{
			Error:   false,
			Message: "success",
			Data:    token,
		}

		app.writeJSON(w, http.StatusOK, payload)
	})

	mux.Get("/test-save-token", func(w http.ResponseWriter, r *http.Request) {
		token, err := app.models.User.Token.GenerateToken(1, 60*time.Minute)
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		user, err := app.models.User.GetOne(2)
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		token.UserID = user.ID
		token.CreatedAt = time.Now()
		token.UpdatedAt = time.Now()

		err = token.Insert(*token, *user)
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		payload := jsonResponse{
			Error:   false,
			Message: "success",
			Data:    token,
		}

		app.writeJSON(w, http.StatusOK, payload)
	})

	mux.Get("/test-validate-token", func(w http.ResponseWriter, r *http.Request) {
		tokenToValidate := r.URL.Query().Get("token")
		valid, err := app.models.Token.ValidToken(tokenToValidate)
		if err != nil {
			app.errorJSON(w, err)
			return
		}

		payload := jsonResponse{
			Error: false,
			Data:  valid,
		}

		app.writeJSON(w, http.StatusOK, payload)
	})

	return mux
}

func (app *application) EditUser(w http.ResponseWriter, r *http.Request) {
	var user data.User
	err := app.readJSON(w, r, &user)
	if err != nil {
		app.errorJSON(w, err)
		return
	}

	if user.ID == 0 {
		//add user
		_, err := app.models.User.Insert(user)
		if err != nil {
			app.errorJSON(w, err)
			return
		}
	} else {
		u, err := app.models.User.GetOne(user.ID)
		if err != nil {
			app.errorJSON(w, err)
			return
		}

		u.Email = user.Email
		u.FirstName = user.FirstName
		u.LastName = user.LastName

		err = u.Update()
		if err != nil {
			app.errorJSON(w, err)
			return
		}

		// if password != empty string, update password
		if user.Password != "" {
			err = u.ResetPassword(user.Password)
			if err != nil {
				app.errorJSON(w, err)
				return
			}
		}
	}

	payload := jsonResponse{
		Error:   false,
		Message: "Changes saved",
	}

	_ = app.writeJSON(w, http.StatusAccepted, payload)
}
