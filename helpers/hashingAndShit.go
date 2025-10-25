package hashingAndShit

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes the password using bcrypt with the specified cost.
// If cost is 0, bcrypt.DefaultCost is used. Returns the hashed password or an error.
func HashPassword(password string, cost int) (string, error) {
	var byteCost int
	if cost <= 0 {
		byteCost = bcrypt.DefaultCost
	} else {
		byteCost = cost
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), byteCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CheckPasswordHash compares a password with its hash. Returns true if the
// password matches the hash, and false otherwise.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
