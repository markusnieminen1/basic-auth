package models

type PermissionsManager interface {
	ListAllPermissions(userId int) (permissions []Permission, err error)
	Add(userId int, permissionToAdd Permission) (err error)
	Remove(userId int, permissionToRemove Permission) (err error)
}
