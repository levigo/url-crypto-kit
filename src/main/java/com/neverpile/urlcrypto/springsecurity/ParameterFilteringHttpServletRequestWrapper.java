package com.neverpile.urlcrypto.springsecurity;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.function.Predicate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * A HttpServletRequestWrapper filtering the request parameters of the original request using a
 * given predicate. Parameters with keys <em>matching</em> the predicate are removed/hidden from the
 * request.
 */
public class ParameterFilteringHttpServletRequestWrapper extends HttpServletRequestWrapper {
  private static class IteratorEnumeration<T> implements Enumeration<T> {
    private final Iterator<T> iterator;

    public IteratorEnumeration(final Iterator<T> iterator) {
        this.iterator = iterator;
    }

    @Override
    public boolean hasMoreElements() {
        return iterator.hasNext();
    }

    @Override
    public T nextElement() {
        return iterator.next();
    }
  }

  
  private final HashMap<String, String[]> filteredParams;

  public ParameterFilteringHttpServletRequestWrapper(final HttpServletRequest request, final Predicate<String> filter) {
    super(request);

    filteredParams = new HashMap<>(request.getParameterMap());

    filteredParams.keySet().removeIf(filter);
  }

  @Override
  public String getParameter(final String name) {
    String[] values = filteredParams.get(name);
    return null == values || values.length == 0 ? null : values[0];
  }

  @Override
  public Enumeration<String> getParameterNames() {
    return new IteratorEnumeration<>(filteredParams.keySet().iterator());
  }

  @Override
  public String[] getParameterValues(final String name) {
    return filteredParams.get(name);
  }

  @Override
  public Map<String, String[]> getParameterMap() {
    return filteredParams;
  }
}
