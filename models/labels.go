package models

import (
	"time"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
)

const UserLevelKey string = "level"

type UserLabel struct {
	ID        string    `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	Label     string    `json:"label" db:"label"`
	State     string    `json:"state" db:"state"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

func NewUserLabel(userID uuid.UUID, label string, state string) *UserLabel {
	userLabel := &UserLabel{
		UserID: userID,
		Label:  label,
		State:  state,
	}
	return userLabel
}

func (UserLabel) TableName() string {
	tableName := "labels"
	return tableName
}

// UpdateState updates the state column of a user label
func (ul *UserLabel) UpdateState(tx *storage.Connection, state string) error {
	ul.State = state
	return tx.UpdateOnly(ul, "state")
}

// FindUserLabels finds all user labels matching the provided user ID
func FindUserLabels(tx *storage.Connection, userID uuid.UUID) (map[string]*UserLabel, error) {
	var labels []*UserLabel

	q := tx.Q().Where("user_id = ?", userID)
	err := q.All(labels)
	if err != nil {
		return nil, err
	}

	res := make(map[string]*UserLabel)
	for _, label := range labels {
		res[label.Label] = label
	}

	return res, nil
}
