/*
 * Copyright (c) 2007-2024, Arshan Dabirsiaghi, Jason Li
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of conditions
 * and the following disclaimer. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. Neither the name of OWASP nor the names of its
 * contributors may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.owasp.validator.html.test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;

/** Public scan coverage for serialized HTML using both DOM and SAX scanners. */
@RunWith(Parameterized.class)
public class HtmlSerializerRoundTripTest {

  private final String description;
  private final String inputHtml;
  private final String expectedSubstring;
  private final int scanner;
  private AntiSamy antiSamy;
  private TestPolicy policy;

  public HtmlSerializerRoundTripTest(
      String description, String inputHtml, String expected, int scanner) {
    this.description = description;
    this.inputHtml = inputHtml;
    this.expectedSubstring = expected;
    this.scanner = scanner;
  }

  @Before
  public void setUp() throws Exception {
    URL url = getClass().getResource("/antisamy.xml");
    policy = TestPolicy.getInstance(url);
    for (String tag : Arrays.asList("dl", "dt", "dd")) {
      policy = policy.mutateTag(policy.getTagByLowercaseName(tag).mutateAction("validate"));
    }
    antiSamy = new AntiSamy();
  }

  @Parameterized.Parameters(name = "{0}, scanner={3}")
  public static Collection<Object[]> data() {
    Collection<Object[]> inputs =
        Arrays.asList(
            new Object[][] {
              // Basic text formatting
              {"bold text", "<b>bold</b>", "<b>bold</b>"},
              {"italic text", "<i>italic</i>", "<i>italic</i>"},
              {"underline text", "<u>underline</u>", "<u>underline</u>"},
              {"strikethrough", "<s>strike</s>", "strike"},
              {"strong text", "<strong>strong</strong>", "<strong>strong</strong>"},
              {"em text", "<em>emphasis</em>", "<em>emphasis</em>"},
              {"code inline", "<code>x=1</code>", "<code>x=1</code>"},
              {"kbd element", "<kbd>Ctrl+C</kbd>", "Ctrl"},
              {"samp element", "<samp>output</samp>", "output"},
              // Headings
              {"h1", "<h1>Heading 1</h1>", "Heading 1"},
              {"h2", "<h2>Heading 2</h2>", "Heading 2"},
              {"h3", "<h3>Heading 3</h3>", "Heading 3"},
              {"h4", "<h4>Heading 4</h4>", "Heading 4"},
              {"h5", "<h5>Heading 5</h5>", "Heading 5"},
              {"h6", "<h6>Heading 6</h6>", "Heading 6"},
              // Lists
              {"ol li", "<ol><li>item</li></ol>", "<li>item</li>"},
              {"ul li", "<ul><li>item</li></ul>", "<li>item</li>"},
              {"dl dt dd", "<dl><dt>term</dt><dd>def</dd></dl>", "term"},
              // Tables
              {"table basic", "<table><tr><td>data</td></tr></table>", "data"},
              {"table with header", "<table><tr><th>head</th></tr></table>", "head"},
              {"table colspan", "<table><tr><td colspan=\"2\">span</td></tr></table>", "span"},
              {"table border", "<table border=\"1\"><tr><td>x</td></tr></table>", "border"},
              // Links
              {"anchor", "<a href=\"http://example.com\">link</a>", "link"},
              {"anchor no href", "<a>text</a>", "text"},
              // Images
              {"img", "<img src=\"x.png\" alt=\"\"/>", "<img"},
              // Form elements
              {"input text", "<input type=\"text\" name=\"x\"/>", "type=\"text\""},
              {
                "input hidden", "<input type=\"hidden\" name=\"x\" value=\"v\"/>", "type=\"hidden\""
              },
              {"select option", "<select><option>a</option></select>", "option"},
              {"textarea", "<textarea>content</textarea>", "content"},
              // Structure
              {"div", "<div>content</div>", "content"},
              {"span", "<span>content</span>", "content"},
              {"p", "<p>content</p>", "content"},
              {"pre", "<pre>  code  </pre>", "  code  "},
              {"blockquote", "<blockquote>quote</blockquote>", "quote"},
              {"abbr", "<abbr title=\"HyperText\">HTML</abbr>", "HTML"},
              {"address", "<address>123 Main St</address>", "123 Main St"},
              {"article", "<article>story</article>", "story"},
              {"aside", "<aside>sidebar</aside>", "sidebar"},
              {"caption", "<table><caption>title</caption><tr><td>d</td></tr></table>", "title"},
              {"cite", "<cite>Author</cite>", "Author"},
              {"del", "<del>removed</del>", "removed"},
              {"dfn", "<dfn>term</dfn>", "term"},
              {"figcaption", "<figure><figcaption>cap</figcaption></figure>", "cap"},
              {"footer", "<footer>foot</footer>", "foot"},
              {"header", "<header>top</header>", "top"},
              {"mark", "<mark>highlighted</mark>", "highlighted"},
              {"nav", "<nav>menu</nav>", "menu"},
              {"section", "<section>sec</section>", "sec"},
              {"small", "<small>fine print</small>", "fine print"},
              // Void elements produce self-closing output
              {"br self-close", "<p>a<br/>b</p>", "<br/>"},
              {"hr self-close", "<p>a</p><hr/><p>b</p>", "<hr/>"},
              // Encoding
              {"amp in text", "<p>a &amp; b</p>", "&amp;"},
              {"lt in text", "<p>a &lt; b</p>", "&lt;"},
              {"gt in text", "<p>a &gt; b</p>", "&gt;"},
              {"nbsp", "<p>&nbsp;</p>", "\u00A0"},
              {"copy", "<p>&copy;</p>", "\u00A9"},
              {"reg", "<p>&reg;</p>", "\u00AE"},
              {"trade", "<p>&trade;</p>", "\u2122"},
              // Nested mixed content
              {"p with inline", "<p><b>b</b> and <i>i</i></p>", "<b>b</b>"},
              {"nested lists", "<ul><li>a<ul><li>b</li></ul></li></ul>", "b"},
              {"blockquote with p", "<blockquote><p>inner</p></blockquote>", "inner"},
              // Attributes
              {"class attr", "<p class=\"foo\">x</p>", "class=\"foo\""},
              {"id attr", "<div id=\"myid\">x</div>", "id=\"myid\""},
              {"style attr", "<span style=\"color:red\">x</span>", "color: red"},
              {"lang attr", "<p lang=\"en\">x</p>", "lang=\"en\""},
              {"dir attr", "<p dir=\"ltr\">x</p>", "x"},
              // data: attributes (may or may not be allowed, test just that output is generated)
              {"target attr", "<a href=\"/\" target=\"_blank\">x</a>", "x"},
            });
    Collection<Object[]> cases = new ArrayList<>();
    for (Object[] input : inputs) {
      for (int scanner : new int[] {AntiSamy.DOM, AntiSamy.SAX}) {
        cases.add(new Object[] {input[0], input[1], input[2], scanner});
      }
    }
    return cases;
  }

  @Test
  public void roundTripContainsExpected() throws Exception {
    CleanResults cr = antiSamy.scan(inputHtml, policy, scanner);
    String result = cr.getCleanHTML();
    assertThat(description + " → " + result, result, containsString(expectedSubstring));
  }
}
