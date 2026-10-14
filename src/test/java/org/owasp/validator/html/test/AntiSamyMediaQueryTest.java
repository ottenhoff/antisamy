/*
 * Copyright (c) 2026, OWASP AntiSamy contributors
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.  Redistributions in binary form must
 * reproduce the above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of OWASP nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.owasp.validator.html.test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.regex.Pattern;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.ScanException;
import org.owasp.validator.html.model.Property;
import org.w3c.css.sac.CSSParseException;

@RunWith(Parameterized.class)
public class AntiSamyMediaQueryTest {
  @Parameterized.Parameters(name = "scanner={0}")
  public static Collection<Object[]> scanners() {
    return Arrays.asList(new Object[][] {{AntiSamy.DOM}, {AntiSamy.SAX}});
  }

  private final int scanner;
  private TestPolicy policy;

  public AntiSamyMediaQueryTest(int scanner) {
    this.scanner = scanner;
  }

  @Before
  public void setUp() throws Exception {
    policy = TestPolicy.getInstance(getClass().getResource("/antisamy.xml"));
    policy =
        policy.addCssProperty(
            new Property(
                "_mediatype",
                Collections.emptyList(),
                Arrays.asList("", "all", "tv", "screen", "print", "handheld"),
                Collections.emptyList(),
                "",
                "remove"));
    for (String feature : Arrays.asList("max-width", "max-device-width", "min-width")) {
      policy =
          policy.addCssProperty(
              new Property(
                  "_mediafeature_" + feature,
                  Collections.singletonList(Pattern.compile("[0-9]+(?:\\.[0-9]+)?px")),
                  Collections.emptyList(),
                  Collections.emptyList(),
                  "",
                  "remove"));
    }
  }

  @Test(timeout = 5000)
  public void commaSeparatedMediaQueriesInsideStyleArePreserved() throws Exception {
    CleanResults result = scan("@media tv, screen and (max-width: 600px) {p {color: red;}}");
    assertThat(result.getCleanHTML(), containsString("@media tv, screen and (max-width: 600.0px)"));
    assertThat(result.getCleanHTML(), containsString("color: red;"));
    assertThat(result.getCleanHTML(), containsString("<p>content</p>"));
  }

  @Test(timeout = 5000)
  public void onlyMediaQueryAfterCommaInsideStyleIsPreserved() throws Exception {
    CleanResults result =
        scan("@media handheld, only screen and (max-device-width: 480px) {p {color: red;}}");
    assertThat(
        result.getCleanHTML(),
        containsString("@media handheld, only screen and (max-device-width: 480.0px)"));
    assertThat(result.getCleanHTML(), containsString("color: red;"));
    assertThat(result.getCleanHTML(), containsString("<p>content</p>"));
  }

  @Test(timeout = 5000)
  public void invalidMediaTypeDoesNotBecomeUnrestrictedAll() throws Exception {
    CleanResults result;
    try {
      result = scan("@media , screen {p {color: red;}} p {color: blue;}");
    } catch (ScanException | CSSParseException rejected) {
      // Rejecting malformed input is safe; rewriting it to match all media is not.
      return;
    }
    assertThat(result.getCleanHTML(), not(containsString("@media all")));
    assertThat(result.getCleanHTML(), containsString("color: blue;"));
    assertThat(result.getCleanHTML(), containsString("<p>content</p>"));
  }

  @Test(timeout = 5000)
  public void mediaQuerySanitizationStillRemovesUnsafeDeclarations() throws Exception {
    CleanResults result =
        scan(
            "@media tv, screen and (max-width: 600px) {p {color: red; behavior: url(javascript:alert(1));}} p {color: blue;}");
    assertThat(result.getCleanHTML(), containsString("color: red;"));
    assertThat(result.getCleanHTML(), containsString("color: blue;"));
    assertThat(result.getCleanHTML(), not(containsString("javascript:")));
    assertThat(result.getCleanHTML(), not(containsString("behavior:")));
  }

  private CleanResults scan(String css) throws Exception {
    return new AntiSamy().scan("<style>" + css + "</style><p>content</p>", policy, scanner);
  }
}
