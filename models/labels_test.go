package models

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/test"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UserLabelsTestSuite struct {
	suite.Suite
	db     *storage.Connection
	Config *conf.GlobalConfiguration
	user   *User
	label  *UserLabel
}

func TestUserLabelsTestSuite(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	ts := &UserLabelsTestSuite{
		db: conn,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *UserLabelsTestSuite) SetupTest() {
	err := TruncateAll(ts.db)
	require.NoError(ts.T(), err, "Failed to truncate tables")

	// Create user
	u, err := NewUser(uuid.Nil, "test@example.com", "secret", "test", nil)
	ts.user = u

	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.db.Create(u), "Error saving new test user")

	// Create label
	l := NewUserLabel(u.ID, "email", "pending")
	require.NoError(ts.T(), ts.db.Create(l), "Error saving new test label")
	ts.label = l
}

func (ts *UserLabelsTestSuite) TestFindUserLabels() {
	labels, err := FindUserLabels(ts.db, ts.user.ID)
	require.NoError(ts.T(), err, "Error finding user labels")
	require.Len(ts.T(), labels, 1, "Expected 1 user label")
	require.Equal(ts.T(), "email", labels["email"].Label, "Expected user label name to match")
	require.Equal(ts.T(), "pending", labels["email"].State, "Expected user label state to match")
}

func (ts *UserLabelsTestSuite) TestUpdateState() {
	err := ts.label.UpdateState(ts.db, "verified")
	require.NoError(ts.T(), err, "Error updating user label state")
}
