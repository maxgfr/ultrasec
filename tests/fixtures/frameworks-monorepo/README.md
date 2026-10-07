Synthetic monorepo for `detectFrameworks`: one framework per package, each
declared the way its ecosystem declares it, with a lockfile where the version
must come from one.

`services/mvc` declares Spring MVC without Spring Boot: the `spring` framework is
versioned as Spring Boot, so it is reported without a version rather than with
Spring Framework's number.
