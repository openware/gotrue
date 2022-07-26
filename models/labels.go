package models

import (
	"time"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
)

type UserLabel struct {
	ID        string    `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	Label     string    `json:"label" db:"label"`
	State     string    `json:"state" db:"state"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

func (UserLabel) TableName() string {
	tableName := "labels"
	return tableName
}

func NewUserLabel(userID uuid.UUID, label string, state string) *UserLabel {
	userLabel := &UserLabel{
		UserID: userID,
		Label:  label,
		State:  state,
	}
	return userLabel
}

// UpdateState updates the state column of a user label
func (ul *UserLabel) UpdateState(tx *storage.Connection, state string) error {
	ul.State = state
	return tx.UpdateOnly(ul, "state")
}

// FindUserLabel finds a user labels matching the provided ID and label name
func FindUserLabel(tx *storage.Connection, userID uuid.UUID, label string) (*UserLabel, error) {
	res := &UserLabel{}
	q := tx.Q().Where("user_id = ? AND label = ?", userID, label)

	err := q.First(res)
	if err != nil {
		return nil, err
	}

	return res, nil
}
