package tests

import (
	ssov1 "github.com/Worwulew/goProtos/gen/go/sso"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sso/tests/suite"
	"testing"
	"time"
)

const (
	emptyAppID = 0
	appID      = 1
	appSecret  = "test-secret"

	passDefaultLen = 10
	deltaSeconds   = 1
)

func TestRegisterLogin_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	regResp, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, regResp.GetUserId())

	logResp, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	loginTime := time.Now()

	token := logResp.Token
	require.NotEmpty(t, token)

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, regResp.GetUserId(), int64(claims["uid"].(float64)))
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)
}

func TestRegisterLogin_DuplicateRegistration(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	regResp, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)
	require.NotEmpty(t, regResp.GetUserId())

	regResp, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.Error(t, err)
	require.Empty(t, regResp.GetUserId())
	require.ErrorContains(t, err, "user already exists")
}

func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	cases := []struct {
		name     string
		email    string
		password string
		expErr   string
	}{
		{
			name:     "Register with empty password",
			email:    gofakeit.Email(),
			password: "",
			expErr:   "password is required",
		},
		{
			name:     "Register with empty email",
			email:    "",
			password: randomFakePassword(),
			expErr:   "email is required",
		},
		{
			name:     "Register with empty email and empty password",
			email:    "",
			password: "",
			expErr:   "email is required",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tc.email,
				Password: tc.password,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.expErr)
		})
	}
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	cases := []struct {
		name     string
		email    string
		password string
		appID    int32
		expErr   string
	}{
		{
			name:     "Login with empty password",
			email:    gofakeit.Email(),
			password: "",
			appID:    appID,
			expErr:   "password is required",
		},
		{
			name:     "Login with empty email",
			email:    "",
			password: randomFakePassword(),
			appID:    appID,
			expErr:   "email is required",
		},
		{
			name:     "Login with empty email and empty password",
			email:    "",
			password: "",
			appID:    appID,
			expErr:   "email is required",
		},
		{
			name:     "Login with not matching password",
			email:    gofakeit.Email(),
			password: randomFakePassword(),
			appID:    appID,
			expErr:   "invalid credentials",
		},
		{
			name:     "Login with empty app_id",
			email:    gofakeit.Email(),
			password: randomFakePassword(),
			appID:    emptyAppID,
			expErr:   "app_id is required",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    gofakeit.Email(),
				Password: randomFakePassword(),
			})
			require.NoError(t, err)

			_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
				Email:    tc.email,
				Password: tc.password,
				AppId:    tc.appID,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.expErr)
		})
	}
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}
