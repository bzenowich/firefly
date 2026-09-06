// Package peercred identifies the process on the other end of a unix socket.
//
// The kernel supplies the credentials, so a peer cannot claim someone else's
// uid. Two places on the appliance need this and neither should trust socket
// permissions alone: fwd-helper, which will only act for fwd, and fwd's label
// server, which will only take app labels from the classifier
// (docs/security-plan.md §3.3, SEC-14).
package peercred
