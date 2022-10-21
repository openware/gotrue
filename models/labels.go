package models

import (
	"time"

	"github.com/gobuffalo/pop/v5"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
)

const (
	UserLevelKey string = "level"
	configFile   string = ""
)

type UserLabel struct {
	ID        uuid.UUID `json:"id" db:"id"`
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

// AfterSave is invoked afterk the user label is saved to
// the database to recalculate the user level
func (ul *UserLabel) AfterSave(tx *pop.Connection) error {
	wrappedTx := &storage.Connection{Connection: tx}

	config, err := conf.LoadConfig(configFile)
	if err != nil {
		return err
	}

	existingLabels, err := FindUserLabels(wrappedTx, ul.UserID)
	if err != nil {
		return err
	}

	user, err := FindUserByID(wrappedTx, ul.UserID)
	if err != nil {
		return err
	}

	newLevel := uint64(0)
levelsLoop:
	for _, levelEntry := range config.UserLabels {
		for _, label := range levelEntry.Labels {
			if _, ok := existingLabels[label]; !ok {
				break levelsLoop
			}
		}
		newLevel++
	}

	if terr := user.UpdateUserMetaData(wrappedTx, map[string]interface{}{
		UserLevelKey: newLevel,
	}); terr != nil {
		return terr
	}
	return nil
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
	err := q.All(&labels)
	if err != nil {
		return nil, err
	}

	res := make(map[string]*UserLabel)
	for _, label := range labels {
		res[label.Label] = label
	}

	return res, nil
}
