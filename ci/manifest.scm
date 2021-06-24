(use-modules (srfi srfi-26)
             (git repository)
             (git reference)
             (git commit)
             (git oid)
             (guix packages)
             (guix git)
             (guix gexp)
             (guix utils)
             (gnu packages bash)
             (gnu packages python)
             (gnu packages python-web)
             (uio packages mreg))

(define (head-commit checkout)
 "Get the current HEAD of CHECKOUT."
  (let* ((repo (repository-open checkout))
         (head (reference-target (repository-head repo)))
         (commit (commit-lookup repo head)))
    (repository-close! repo)
    (oid->string head)))

;; Use the HEAD of the local checkout unless running on the CI.
(define %repository
  (or (and=> (getenv "GITHUB_SERVER_URL")
             (cut string-append <> "/" (getenv "GITHUB_REPOSITORY")))
      (dirname (dirname (current-filename)))))

(define %commit (or (getenv "GITHUB_SHA")
                    (head-commit %repository)))

(define mreg/dev
  (package
    (inherit mreg)
    (version (string-append "0.0+" (string-take %commit 7)))
    (source (git-checkout (url %repository) (commit %commit)))))

;; Script to run migrations and start a gunicorn server, used as the
;; "entry point" in the Docker container.
;; Note: To use custom site settings, bind a customized "mregsite"
;; directory to /app/mregsite, like so:
;;  --mount type=bind,source=$HOME/localsettings,destination=/app/mregsite
(define (mreg-wrapper mreg)
  (with-imported-modules '((guix build utils))
    (computed-file
     "mreg-wrapper"
     #~(begin
         (use-modules (guix build utils)
                      (ice-9 format))
         (let ((bash #$(file-append bash-minimal "/bin/bash"))
               (gunicorn #$(file-append gunicorn "/bin/gunicorn"))
               (wrapper (string-append #$output "/bin/mreg-wrapper"))
               (mreg #$(file-append mreg "/lib/python"
                                    (version-major+minor (package-version python))
                                    "/site-packages/mreg")))
           (mkdir-p (string-append #$output "/bin"))
           (copy-recursively mreg (string-append #$output "/app"))
           (call-with-output-file wrapper
             (lambda (port)
               (format port "#!~a
export PYTHONPATH=\"/app:$PYTHONPATH\"
cd /app
python manage.py migrate --noinput
exec ~a $@ mregsite.wsgi
"
                       bash gunicorn)))
           (chmod wrapper #o555))))))

(manifest
 (append (list (manifest-entry
                 (version "0")
                 (name "mreg-wrapper")
                 (item (mreg-wrapper mreg/dev))))
         (manifest-entries
          (packages->manifest
           (list mreg/dev python-wrapper)))))
