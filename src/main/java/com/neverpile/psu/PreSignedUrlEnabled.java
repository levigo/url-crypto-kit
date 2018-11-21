package com.neverpile.psu;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Methods can be annotated with the annotation PSUEnabled.
 * The annotation serves as a flag and allows the creation of a pre signed url on the requested url.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface PreSignedUrlEnabled {
}
