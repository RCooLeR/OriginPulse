package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"originpulse/internal/config"
	"originpulse/internal/db"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrSessionNotFound    = errors.New("session not found")
	ErrUserNotFound       = errors.New("user not found")
	ErrLastActiveUser     = errors.New("cannot disable the last active user")
)

type User struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name,omitempty"`
	Role        string     `json:"role"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

type UpdateUserOptions struct {
	Email       *string
	DisplayName *string
	IsActive    *bool
	Password    *string
}

type Service struct {
	db         *db.Store
	cookieName string
	sessionTTL time.Duration
	secure     bool
}

func NewService(store *db.Store, cfg config.AuthConfig) *Service {
	return &Service{
		db:         store,
		cookieName: cfg.SessionCookieName,
		sessionTTL: cfg.SessionTTL,
		secure:     cfg.SecureCookies,
	}
}

func (s *Service) Enabled() bool {
	return s != nil && s.db != nil && s.db.Enabled()
}

func (s *Service) CookieName() string {
	return s.cookieName
}

func (s *Service) SecureCookies() bool {
	return s.secure
}

func (s *Service) CreateUser(ctx context.Context, email string, password string, displayName string) (User, error) {
	pool, err := s.db.Pool()
	if err != nil {
		return User{}, err
	}

	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return User{}, errors.New("email is required")
	}

	passwordHash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}

	var user User
	err = pool.QueryRow(ctx, `
INSERT INTO users (email, password_hash, display_name)
VALUES ($1, $2, $3)
ON CONFLICT (email) DO UPDATE
SET password_hash = EXCLUDED.password_hash,
    display_name = EXCLUDED.display_name,
    is_active = true,
    updated_at = now()
RETURNING id::text, email::text, coalesce(display_name, ''), is_active, created_at, last_login_at`,
		email, passwordHash, nullableString(displayName),
	).Scan(&user.ID, &user.Email, &user.DisplayName, &user.IsActive, &user.CreatedAt, &user.LastLoginAt)
	user.Role = "user"
	return user, err
}

func (s *Service) Authenticate(ctx context.Context, email string, password string, userAgent string) (User, string, error) {
	pool, err := s.db.Pool()
	if err != nil {
		return User{}, "", err
	}

	var user User
	var passwordHash string
	err = pool.QueryRow(ctx, `
SELECT id::text, email::text, coalesce(display_name, ''), is_active, created_at, last_login_at, password_hash
FROM users
WHERE email = $1 AND is_active = true`, strings.TrimSpace(strings.ToLower(email)),
	).Scan(&user.ID, &user.Email, &user.DisplayName, &user.IsActive, &user.CreatedAt, &user.LastLoginAt, &passwordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, "", ErrInvalidCredentials
	}
	if err != nil {
		return User{}, "", err
	}

	ok, err := VerifyPassword(password, passwordHash)
	if err != nil || !ok {
		return User{}, "", ErrInvalidCredentials
	}

	rawToken, err := randomToken()
	if err != nil {
		return User{}, "", err
	}

	tokenHash := hashToken(rawToken)
	expiresAt := time.Now().UTC().Add(s.sessionTTL)
	if _, err := pool.Exec(ctx, `
INSERT INTO sessions (user_id, token_hash, user_agent, expires_at)
VALUES ($1, $2, $3, $4)`, user.ID, tokenHash, userAgent, expiresAt); err != nil {
		return User{}, "", err
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1`, user.ID); err != nil {
		return User{}, "", err
	}
	user.Role = "user"

	return user, rawToken, nil
}

func (s *Service) UserForToken(ctx context.Context, rawToken string) (User, error) {
	pool, err := s.db.Pool()
	if err != nil {
		return User{}, err
	}
	if strings.TrimSpace(rawToken) == "" {
		return User{}, ErrSessionNotFound
	}

	var user User
	err = pool.QueryRow(ctx, `
SELECT u.id::text, u.email::text, coalesce(u.display_name, ''), u.is_active, u.created_at, u.last_login_at
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token_hash = $1
  AND s.expires_at > now()
  AND u.is_active = true`, hashToken(rawToken),
	).Scan(&user.ID, &user.Email, &user.DisplayName, &user.IsActive, &user.CreatedAt, &user.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrSessionNotFound
	}
	user.Role = "user"
	return user, err
}

func (s *Service) DeleteSession(ctx context.Context, rawToken string) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	if strings.TrimSpace(rawToken) == "" {
		return nil
	}
	_, err = pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, hashToken(rawToken))
	return err
}

func (s *Service) UpdateUser(ctx context.Context, id string, opts UpdateUserOptions) (User, error) {
	pool, err := s.db.Pool()
	if err != nil {
		return User{}, err
	}

	id = strings.TrimSpace(id)
	if id == "" {
		return User{}, ErrUserNotFound
	}

	var email any
	if opts.Email != nil {
		normalized := strings.TrimSpace(strings.ToLower(*opts.Email))
		if normalized == "" {
			return User{}, errors.New("email is required")
		}
		email = normalized
	}

	displayNameSet := opts.DisplayName != nil
	var displayName any
	if displayNameSet {
		displayName = nullableString(*opts.DisplayName)
	}

	var passwordHash any
	if opts.Password != nil {
		password := strings.TrimSpace(*opts.Password)
		if password == "" {
			return User{}, errors.New("password is required")
		}
		hash, err := HashPassword(password)
		if err != nil {
			return User{}, err
		}
		passwordHash = hash
	}

	if opts.IsActive != nil && !*opts.IsActive {
		if err := s.ensureNotLastActiveUser(ctx, id); err != nil {
			return User{}, err
		}
	}
	var isActive any
	if opts.IsActive != nil {
		isActive = *opts.IsActive
	}

	var user User
	err = pool.QueryRow(ctx, `
UPDATE users
SET email = coalesce($2::citext, email),
    display_name = CASE WHEN $3 THEN $4::text ELSE display_name END,
    is_active = coalesce($5::boolean, is_active),
    password_hash = coalesce($6::text, password_hash),
    updated_at = now()
WHERE id = $1
RETURNING id::text, email::text, coalesce(display_name, ''), is_active, created_at, last_login_at`,
		id,
		email,
		displayNameSet,
		displayName,
		isActive,
		passwordHash,
	).Scan(&user.ID, &user.Email, &user.DisplayName, &user.IsActive, &user.CreatedAt, &user.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, err
	}

	if opts.IsActive != nil && !*opts.IsActive {
		if _, err := pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
			return User{}, err
		}
	}
	user.Role = "user"
	return user, nil
}

func (s *Service) DeleteUser(ctx context.Context, id string) (User, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return User{}, ErrUserNotFound
	}
	if err := s.ensureNotLastActiveUser(ctx, id); err != nil {
		return User{}, err
	}
	inactive := false
	return s.UpdateUser(ctx, id, UpdateUserOptions{IsActive: &inactive})
}

func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	pool, err := s.db.Pool()
	if err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx, `
SELECT id::text, email::text, coalesce(display_name, ''), is_active, created_at, last_login_at
FROM users
ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Email, &user.DisplayName, &user.IsActive, &user.CreatedAt, &user.LastLoginAt); err != nil {
			return nil, err
		}
		user.Role = "user"
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Service) ensureNotLastActiveUser(ctx context.Context, id string) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}

	var isActive bool
	if err := pool.QueryRow(ctx, `SELECT is_active FROM users WHERE id = $1`, id).Scan(&isActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return err
	}
	if !isActive {
		return nil
	}

	var activeCount int
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM users WHERE is_active = true`).Scan(&activeCount); err != nil {
		return err
	}
	if activeCount <= 1 {
		return ErrLastActiveUser
	}
	return nil
}

func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

func nullableString(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}
