(use-modules (guix packages)
             (guix git)
             (guix gexp)
             (guix utils)
             (gnu packages bash)
             (gnu packages python)
             (gnu packages python-web)
             (uio packages mreg))

;; Use the HEAD of the local checkout unless running on the CI.
(define %commit (getenv "GITHUB_SHA"))
(define %uri (if %commit
                 (string-append (getenv "GITHUB_SERVER_URL") "/"
                                (getenv "GITHUB_REPOSITORY"))
                 (dirname (dirname (current-filename)))))

(define mreg/dev
  (package
    (inherit mreg)
    (version (string-append "0.0+" (if %commit (string-take %commit 7) "dev")))
    (source (git-checkout (url %uri) (commit %commit)))))

;; Script to run migrations and start a gunicorn server, used as the
;; "entry point" in the Docker container.
;; Note: To use custom site settings, bind a customized "mregsite"
;; directory to /app/mregsite, like so:
;;  --mount type=bind,source=$HOME/localsettings,destination=/app/mregsite
(define* (mreg-wrapper mreg #:optional (args '()))
  (let ((gunicorn (car (assoc-ref (package-propagated-inputs mreg)
                                  "gunicorn"))))
    (with-imported-modules '((guix build utils))
      (computed-file
       "mreg-wrapper"
       #~(begin
           (use-modules (guix build utils)
                        (ice-9 format))
           (let* ((bash #$(file-append bash-minimal "/bin/bash"))
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
exec ~a ~a
"
                         bash gunicorn (string-join '#$args " "))))
             (chmod wrapper #o555)))))))

(define %entry-point
  (mreg-wrapper
   mreg/dev
   '("--bind=0.0.0.0" "--workers" "3" "mregsite.wsgi")))

(manifest
 (append (list (manifest-entry
                 (version "0")
                 (name "mreg-wrapper")
                 (item %entry-point)))
         (manifest-entries
          (packages->manifest
           (list mreg/dev python-wrapper)))))
