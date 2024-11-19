package main

import (
	"GoCourse/internal/data"
	"GoCourse/internal/validator"
	"errors"
	"expvar"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Connection", "close")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (app *application) rateLimit(next http.Handler) http.Handler {

	type client struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}

	var (
		mu      sync.Mutex
		clients = make(map[string]*client)
	)

	go func() {
		for {
			time.Sleep(time.Minute)

			mu.Lock()

			for ip, client := range clients {
				if time.Since(client.lastSeen) > 3*time.Minute {
					delete(clients, ip)
				}
			}

			mu.Unlock()
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if app.config.limiter.enabled {
			IP, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				app.serverErrorResponse(w, r, err)
				return
			}

			mu.Lock()

			if _, found := clients[IP]; !found {
				clients[IP] = &client{
					limiter: rate.NewLimiter(rate.Limit(app.config.limiter.rps), app.config.limiter.burst),
				}
			}

			clients[IP].lastSeen = time.Now()

			if !clients[IP].limiter.Allow() {
				mu.Unlock()
				app.rateLimitExceededResponse(w, r)
				return
			}

			mu.Unlock()
		}

		next.ServeHTTP(w, r)
	})
}

func (app *application) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Authorization")

		authorizationHeader := r.Header.Get("Authorization")

		if authorizationHeader == "" {
			r = app.contextSetUser(r, data.AnonymousUser)
			next.ServeHTTP(w, r)
			return
		}

		headerParts := strings.Split(authorizationHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			app.invalidAuthenticationTokenResponse(w, r)
			return
		}

		token := headerParts[1]

		v := validator.New()

		if data.ValidateTokenPlaintext(v, token); !v.Valid() {
			app.invalidAuthenticationTokenResponse(w, r)
			return
		}

		user, err := app.models.Users.GetForToken(data.ScopeAuthentication, token)
		if err != nil {
			switch {
			case errors.Is(err, data.ErrRecordNotFound):
				app.invalidAuthenticationTokenResponse(w, r)
			default:
				app.serverErrorResponse(w, r, err)
			}
			return
		}

		r = app.contextSetUser(r, user)

		next.ServeHTTP(w, r)
	})
}

func (app *application) requireAuthenticatedUser(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := app.contextGetUser(r)

		if user.IsAnonymous() {
			app.authenticationRequiredResponse(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (app *application) requireActivatedUser(next http.HandlerFunc) http.HandlerFunc {
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := app.contextGetUser(r)

		if !user.Activated {
			app.inactiveAccountResponse(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})

	return app.requireAuthenticatedUser(fn)
}

func (app *application) requirePermission(code string, next http.HandlerFunc) http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		user := app.contextGetUser(r)

		permissions, err := app.models.Permissions.GetAllForUser(user.ID)
		if err != nil {
			app.serverErrorResponse(w, r, err)
			return
		}

		if !permissions.Include(code) {
			app.notPermittedResponse(w, r)
			return
		}

		next.ServeHTTP(w, r)
	}

	return app.requireActivatedUser(fn)
}

func (app *application) enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")

		w.Header().Add("Vary", "Access-Control-Request-Method")

		origin := r.Header.Get("Origin")

		if origin != "" {
			for i := range app.config.cors.trustedOrigins {
				if origin == app.config.cors.trustedOrigins[i] {
					w.Header().Set("Access-Control-Allow-Origin", origin)

					if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
						w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, PUT, PATCH, DELETE")
						w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

						w.WriteHeader(http.StatusOK)
						return
					}
					break
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// Тип metricsResponseWriter оборачивает существующий http.ResponseWriter
// и содержит поле для записи кода состояния ответа, а также булевый флаг,
// указывающий, были ли уже отправлены заголовки ответа.
type metricsResponseWriter struct {
	wrapped       http.ResponseWriter // Обернутый http.ResponseWriter.
	statusCode    int                 // Код состояния HTTP-ответа.
	headerWritten bool                // Флаг, показывающий, отправлены ли заголовки.
}

// Эта функция возвращает новый экземпляр metricsResponseWriter, который
// оборачивает переданный http.ResponseWriter. Код состояния по умолчанию
// устанавливается в 200, так как это стандартный код ответа в Go.
func newMetricsResponseWriter(w http.ResponseWriter) *metricsResponseWriter {
	return &metricsResponseWriter{
		wrapped:    w,             // Устанавливаем обернутый writer.
		statusCode: http.StatusOK, // Код состояния по умолчанию — 200.
	}
}

// Метод Header() просто вызывает метод Header() у обернутого http.ResponseWriter.
func (mw *metricsResponseWriter) Header() http.Header {
	return mw.wrapped.Header()
}

// Метод WriteHeader() также вызывает WriteHeader() у обернутого
// http.ResponseWriter. После этого мы записываем код состояния ответа
// (если он еще не был записан) и устанавливаем флаг headerWritten в true,
// указывая, что заголовки HTTP-ответа были отправлены.
func (mw *metricsResponseWriter) WriteHeader(statucCode int) {
	mw.wrapped.WriteHeader(statucCode) // Передаем код состояния в обернутый writer.
	if !mw.headerWritten {             // Если заголовки еще не отправлены...
		mw.statusCode = statucCode // Записываем код состояния.
		mw.headerWritten = true    // Устанавливаем флаг отправки заголовков.
	}
}

// Метод Write() вызывает метод Write() у обернутого http.ResponseWriter.
// Поскольку вызов Write() автоматически отправляет заголовки ответа,
// мы устанавливаем флаг headerWritten в true.
func (mw *metricsResponseWriter) Write(b []byte) (int, error) {
	mw.headerWritten = true
	return mw.wrapped.Write(b)
}

// Метод Unwrap() возвращает обернутый http.ResponseWriter.
func (mw *metricsResponseWriter) Unwrap() http.ResponseWriter {
	return mw.wrapped
}

func (app *application) metrics(next http.Handler) http.Handler {
	// Инициализируйте новые переменные expvar при первом построении цепочки промежуточного ПО.
	var (
		totalRequestsReceived           = expvar.NewInt("total_request_received")
		totalResponsesSent              = expvar.NewInt("total_responses_sent")
		totalProcessingTimeMicroseconds = expvar.NewInt("total_processing_time_μs")
		// Объявите новую карту expvar для хранения количества ответов для каждого кода статуса HTTP
		totalResponsesSentByStatus = expvar.NewMap("total_responses_sent_by_status")
	)
	// Следующий код будет выполняться для каждого запроса...
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Запишите время, в течение которого мы начали обрабатывать запрос.
		start := time.Now()
		// Используйте метод Add() для увеличения количества полученных запросов на 1
		totalRequestsReceived.Add(1)

		// Создаем новый metricsResponseWriter, который оборачивает исходный 
		// http.ResponseWriter, полученное метриками промежуточным программным обеспечением.
		mw := newMetricsResponseWriter(w)

		// Вызовите следующий обработчик в цепочке, используя новый metricsResponseWriter 
		// в качестве http. Значение ResponseWriter.
		next.ServeHTTP(mw, r)

		// Возвращаясь вверх по цепочке промежуточного ПО, увеличьте количество отправленных ответов на 1.
		totalResponsesSent.Add(1)

		// На этом этапе код статуса ответа должен быть сохранен в поле 
		// mw.statusCode. Обратите внимание, что карта expvar имеет строковый ключ, поэтому нам 
		// необходимо использовать функция strconv.Itoa() для преобразования кода состояния 
		// (который является целым числом) в строку. Затем мы используем метод Add() на 
		// нашей новой карте totalResponsesSentByStatus, чтобы увеличить счетчик для 
		// заданного кода состояния на 1.
		totalResponsesSentByStatus.Add(strconv.Itoa(mw.statusCode), 1)

		// Подсчитываем количество микросекунд с момента начала обработки запроса,
		// затем увеличиваем общее время обработки на эту величину.
		duration := time.Since(start).Microseconds()
		totalProcessingTimeMicroseconds.Add(duration)
	})
}