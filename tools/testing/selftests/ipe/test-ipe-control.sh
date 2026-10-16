#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Run once on a disposable test system booted with IPE enabled and without a
# boot policy. The test finishes by denying every IPE control operation, so a
# second run requires a reboot.
#
# The test kernel must trust ipe-test-cert.pem. The accompanying config
# fragment adds it to CONFIG_SYSTEM_TRUSTED_KEYS.
#
# Requirements: root with CAP_MAC_ADMIN and openssl.
# shellcheck disable=SC2329 # helpers are invoked indirectly by expect_success

DIR="$(dirname "$(readlink -f "$0")")"
# shellcheck source=../kselftest/ktap_helpers.sh
source "${DIR}/../kselftest/ktap_helpers.sh"

SECURITYFS=/sys/kernel/security
IPEFS="$SECURITYFS/ipe"
WORK_DIR=
MOUNTED_SECURITYFS=0
PRIMARY="ipe_control_primary_$$"
ALTERNATE="ipe_control_alternate_$$"
ACTIVATION_TARGET="ipe_control_activation_target_$$"
DELETE_TARGET="ipe_control_delete_target_$$"
LATE_POLICY="ipe_control_late_$$"
BLOCKED_POLICY="ipe_control_blocked_$$"

skip()
{
	ktap_skip_all "$*"
	exit "$KSFT_SKIP"
}

fail()
{
	ktap_test_fail "$*"
	ktap_finished
}

cleanup()
{
	if [ "$MOUNTED_SECURITYFS" -eq 1 ]; then
		umount "$SECURITYFS" 2>/dev/null || true
	fi

	if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
		rm -rf -- "$WORK_DIR"
	fi
}

trap cleanup EXIT

require_command()
{
	command -v "$1" >/dev/null 2>&1 || skip "missing command: $1"
}

make_signed_policy()
{
	local name=$1
	local version=$2
	local tag=$3
	local policy="$WORK_DIR/$tag.policy"
	local signature="$WORK_DIR/$tag.p7b"
	local op

	shift 3
	{
		printf 'policy_name=%s policy_version=%s\n' "$name" "$version"
		printf 'op=EXECUTE action=ALLOW\n'
		printf 'op=FIRMWARE action=ALLOW\n'
		printf 'op=KMODULE action=ALLOW\n'
		printf 'op=KEXEC_IMAGE action=ALLOW\n'
		printf 'op=KEXEC_INITRAMFS action=ALLOW\n'
		printf 'op=POLICY action=ALLOW\n'
		printf 'op=X509_CERT action=ALLOW\n'
		printf 'DEFAULT action=DENY\n'
		for op in "$@"; do
			printf 'op=%s action=DENY\n' "$op"
		done
	} > "$policy"

	if ! openssl smime -sign -in "$policy" \
		-signer "$DIR/ipe-test-cert.pem" \
		-inkey "$DIR/ipe-test-key.pem" \
		-noattr -nodetach -nosmimecap -outform DER \
		-out "$signature" > /dev/null 2> "$WORK_DIR/openssl.log"; then
		cat "$WORK_DIR/openssl.log" >&2
		fail "sign the $tag policy"
	fi
}

load_policy()
{
	local tag=$1

	cat "$WORK_DIR/$tag.p7b" > "$IPEFS/new_policy"
}

update_primary()
{
	local version=$1
	local tag=$2

	shift 2
	make_signed_policy "$PRIMARY" "$version" "$tag" "$@"
	cat "$WORK_DIR/$tag.p7b" > "$IPEFS/policies/$PRIMARY/update"
}

activate_policy()
{
	printf 1 > "$IPEFS/policies/$1/active"
}

delete_policy()
{
	printf 1 > "$IPEFS/policies/$1/delete"
}

set_enforcement()
{
	printf '%s' "$1" > "$IPEFS/enforce"
}

set_success_audit()
{
	printf '%s' "$1" > "$IPEFS/success_audit"
}

expect_success()
{
	local description=$1

	shift
	if "$@" 2> "$WORK_DIR/command.err"; then
		ktap_test_pass "$description"
	else
		cat "$WORK_DIR/command.err" >&2
		fail "$description"
	fi
}

load_bootstrap_policies()
{
	load_policy primary-v1 &&
	load_policy alternate-v1 &&
	load_policy activation-target-v99 &&
	load_policy delete-target-v1
}

exercise_compatible_activation()
{
	activate_policy "$ALTERNATE" && activate_policy "$PRIMARY"
}

exercise_compatible_audit_controls()
{
	set_success_audit 0 && set_success_audit 1 && set_success_audit 0
}

exercise_compatible_enforcement_controls()
{
	set_enforcement 0 && set_enforcement 1
}

assert_load_denied()
{
	! load_policy blocked-load && [ ! -e "$IPEFS/policies/$BLOCKED_POLICY" ]
}

assert_delete_denied()
{
	! delete_policy "$LATE_POLICY" &&
		[ -e "$IPEFS/policies/$LATE_POLICY" ]
}

assert_activation_denied()
{
	! activate_policy "$ACTIVATION_TARGET" &&
		[ "$(cat "$IPEFS/policies/$PRIMARY/active")" = 1 ]
}

assert_enforcement_off_denied()
{
	! set_enforcement 0 && [ "$(cat "$IPEFS/enforce")" = 1 ]
}

assert_audit_on_denied()
{
	! set_success_audit 1 && [ "$(cat "$IPEFS/success_audit")" = 0 ]
}

assert_audit_off_denied()
{
	! set_success_audit 0 && [ "$(cat "$IPEFS/success_audit")" = 1 ]
}

assert_update_denied()
{
	! cat "$WORK_DIR/final-v12.p7b" > "$IPEFS/policies/$PRIMARY/update" &&
		[ "$(cat "$IPEFS/policies/$PRIMARY/version")" = 0.0.11 ]
}

assert_final_load_denied()
{
	! load_policy final-load && [ ! -e "$IPEFS/policies/$BLOCKED_POLICY" ]
}

bootstrap()
{
	local active
	local cap_eff
	local command

	for command in awk cat id mktemp mount openssl rm umount; do
		require_command "$command"
	done

	[ "$(id -u)" -eq 0 ] || skip "root privileges are required"

	cap_eff=$(awk '/^CapEff:/ { print $2 }' /proc/self/status)
	[ -n "$cap_eff" ] || skip "cannot read effective capabilities"
	(( (16#$cap_eff & (1 << 33)) != 0 )) ||
		skip "CAP_MAC_ADMIN is required"

	if [ ! -d "$IPEFS" ]; then
		mount -t securityfs none "$SECURITYFS" 2>/dev/null ||
			skip "securityfs is unavailable"
		MOUNTED_SECURITYFS=1
	fi

	[ -w "$IPEFS/new_policy" ] || skip "IPE is not enabled"
	[ -r "$DIR/ipe-test-cert.pem" ] || skip "missing test certificate"
	[ -r "$DIR/ipe-test-key.pem" ] || skip "missing test private key"

	for active in "$IPEFS"/policies/*/active; do
		[ -e "$active" ] || break
		[ "$(cat "$active")" = 0 ] ||
			skip "the test requires no active boot policy"
	done

	WORK_DIR=$(mktemp -d -t ipe-control-selftest.XXXXXX) ||
		skip "cannot create a temporary directory"

	set_enforcement 1 || skip "cannot enable IPE enforcement"
	set_success_audit 0 || skip "cannot disable IPE success auditing"
}

ktap_print_header
bootstrap
ktap_set_plan 24

make_signed_policy "$PRIMARY" 0.0.1 primary-v1
make_signed_policy "$ALTERNATE" 0.0.1 alternate-v1
make_signed_policy "$ACTIVATION_TARGET" 0.0.99 activation-target-v99
make_signed_policy "$DELETE_TARGET" 0.0.1 delete-target-v1
expect_success "load policies before one is active" load_bootstrap_policies
expect_success "activate the initial policy" activate_policy "$PRIMARY"

# The global DENY in every policy must not govern omitted control operations.
make_signed_policy "$LATE_POLICY" 0.0.1 late-v1
expect_success "an omitted policy-load operation is allowed" load_policy late-v1
expect_success "an omitted policy-delete operation is allowed" \
	delete_policy "$DELETE_TARGET"
expect_success "an omitted policy-activation operation is allowed" \
	exercise_compatible_activation
expect_success "an omitted policy-update operation is allowed" \
	update_primary 0.0.2 primary-v2
expect_success "omitted success-audit operations are allowed" \
	exercise_compatible_audit_controls
expect_success "omitted enforcement operations are allowed" \
	exercise_compatible_enforcement_controls

make_signed_policy "$BLOCKED_POLICY" 0.0.1 blocked-load
update_primary 0.0.3 primary-v3 IPE_CONTROL_POLICY_LOAD ||
	fail "install the policy-load denial"
expect_success "an explicit policy-load rule denies loading" assert_load_denied

update_primary 0.0.4 primary-v4 IPE_CONTROL_POLICY_DELETE ||
	fail "install the policy-delete denial"
expect_success "an explicit policy-delete rule denies deletion" \
	assert_delete_denied

update_primary 0.0.5 primary-v5 IPE_CONTROL_POLICY_ACTIVATION ||
	fail "install the policy-activation denial"
expect_success "an explicit policy-activation rule denies activation" \
	assert_activation_denied

update_primary 0.0.6 primary-v6 IPE_CONTROL_ENFORCEMENT_OFF ||
	fail "install the enforcement-off denial"
expect_success "an explicit enforcement-off rule denies permissive mode" \
	assert_enforcement_off_denied

update_primary 0.0.7 primary-v7 IPE_CONTROL_SUCCESS_AUDIT_ON ||
	fail "install the success-audit-on denial"
expect_success "an explicit success-audit-on rule denies the change" \
	assert_audit_on_denied

update_primary 0.0.8 primary-v8 IPE_CONTROL_SUCCESS_AUDIT_OFF ||
	fail "install the success-audit-off denial"
set_success_audit 1 || fail "enable success auditing before testing its denial"
expect_success "an explicit success-audit-off rule denies the change" \
	assert_audit_off_denied

update_primary 0.0.9 primary-v9 || fail "install the permissive-mode policy"
set_enforcement 0 || fail "enter permissive mode"
update_primary 0.0.10 primary-v10 IPE_CONTROL_ENFORCEMENT_ON ||
	fail "install the enforcement-on denial"
expect_success "enforcement-on denial is permissive while enforcement is off" \
	set_enforcement 1

update_primary 0.0.11 primary-v11 \
	IPE_CONTROL_POLICY_LOAD \
	IPE_CONTROL_POLICY_UPDATE \
	IPE_CONTROL_POLICY_ACTIVATION \
	IPE_CONTROL_POLICY_DELETE \
	IPE_CONTROL_ENFORCEMENT_ON \
	IPE_CONTROL_ENFORCEMENT_OFF \
	IPE_CONTROL_SUCCESS_AUDIT_ON \
	IPE_CONTROL_SUCCESS_AUDIT_OFF || fail "install the final sealed policy"
ktap_test_pass "install a policy that denies every control operation"

make_signed_policy "$BLOCKED_POLICY" 0.0.2 final-load
make_signed_policy "$PRIMARY" 0.0.12 final-v12
expect_success "the sealed policy denies policy loading" assert_final_load_denied
expect_success "the sealed policy denies policy updates" assert_update_denied
expect_success "the sealed policy denies policy activation" \
	assert_activation_denied
expect_success "the sealed policy denies policy deletion" assert_delete_denied
expect_success "the sealed policy denies disabling enforcement" \
	assert_enforcement_off_denied
expect_success "the sealed policy denies disabling success auditing" \
	assert_audit_off_denied
expect_success "writing the current enforcement value remains a no-op" \
	set_enforcement 1
expect_success "writing the current success-audit value remains a no-op" \
	set_success_audit 1

ktap_finished
