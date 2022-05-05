#define _GNU_SOURCE
#include <string.h>
#include <syslog.h>
#include <sys/smack.h>

#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#define DEFAULT_LABEL "User"

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags,
                      int argc, const char **argv)
{
  return PAM_IGNORE;
}

/*
When opening session, the arguments are searched for a value
of kind "user=label". If not found, but the value "=label" exists
in parameters, it will be used.
Otherwise, the value DEFAULT_LABEL is used.
When the value of the label is the empty string, no change is made.
*/

PAM_EXTERN int 
pam_sm_open_session (pam_handle_t *pamh,
         int flags,
         int argc,
         const char **argv)
{
  const char *label = NULL;
  int rc, idx;
  unsigned lenu;
  const char *user;
  if (smack_smackfs_path ()) {
    /* compute the label for the user */
    rc = pam_get_user(pamh, &user, NULL);
    if (rc == PAM_SUCCESS && user != NULL && *user != '\0') {
      lenu = (unsigned)strlen(user);
      for (idx = 0 ; idx < argc && label == NULL ; idx++) {
        if (0 == strncmp(argv[idx], user, lenu)
         && argv[idx][lenu] == '='
         &&  argv[idx][lenu + 1] != '\0') {
          /* set label if arg is "user=label" */
          label = &argv[idx][lenu + 1];
	 }
      }
    }
    /* compute the default label if none is set for user */
    if (label == NULL) {
      for (idx = 0 ; idx < argc && label == NULL ; idx++)
	if (argv[idx][0] == '=')
          label = &argv[idx][1];
      if (label == NULL)
        label = DEFAULT_LABEL;
    }
    if (label != NULL && *label != '\0') {
      rc = smack_set_label_for_self (label);
      if (rc) {
        pam_syslog (pamh, LOG_WARNING, "couldn't set Smack's label");
        return PAM_SESSION_ERR;
      }
    }
  }
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_smack_modstruct = {
  "pam_smack",
  NULL,
  NULL,
  NULL,
  pam_sm_open_session,
  pam_sm_close_session,
  NULL,
};

#endif

