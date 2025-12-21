use crate::{blocker::AdblockRequester, statistics::Statistics};
use bytes::Bytes;
use crossbeam_channel::Receiver;
use hyper::body::Frame;
use lol_html::{element, HtmlRewriter, Settings};
use regex::Regex;
use std::collections::HashSet;
use std::fmt::Write;
use tokio::sync::mpsc::Sender;

pub struct Rewriter {
    url: String,
    adblock_requester: AdblockRequester,
    receiver: Receiver<Bytes>,
    body_sender: Sender<Result<Frame<Bytes>, hyper::Error>>,
    statistics: Statistics,
}

impl Rewriter {
    pub(crate) fn new(
        url: String,
        adblock_requester: AdblockRequester,
        receiver: Receiver<Bytes>,
        body_sender: Sender<Result<Frame<Bytes>, hyper::Error>>,
        statistics: Statistics,
    ) -> Self {
        Self {
            url,
            body_sender,
            statistics,
            adblock_requester,
            receiver,
        }
    }

    pub(crate) fn rewrite(self) {
        let body_sender = self.body_sender;
        let adblock_requester = self.adblock_requester.clone();
        let statistics = self.statistics.clone();
        let url = self.url.clone();

        let mut classes = HashSet::new();
        let mut ids = HashSet::new();

        let body_sender_clone = body_sender.clone();
        
        let mut rewriter = HtmlRewriter::new(
            Settings {
                element_content_handlers: vec![
                    element!("*", |element| {
                        let id = element.get_attribute("id");

                        if let Some(id) = id {
                            ids.insert(id);
                        }

                        Ok(())
                    }),
                    element!("*", |element| {
                        let class = element.get_attribute("class");

                        if let Some(class) = class {
                            let re = Regex::new(r"\s+").unwrap();
                            let classes_without_duplicate_spaces = re.replace_all(&class, " ");

                            let class = classes_without_duplicate_spaces
                                .split(' ')
                                .map(|s| s.to_string())
                                .collect::<HashSet<_>>();

                            classes.extend(class);
                        }

                        Ok(())
                    }),
                ],
                ..Settings::default()
            },
            move |c: &[u8]| {
                let _ = body_sender_clone.blocking_send(Ok(Frame::data(Bytes::copy_from_slice(c))));
            },
        );

        for message in self.receiver {
            if rewriter.write(&message).is_err() {
                break;
            }
        }
        let _ = rewriter.end();

        // Now inject the cosmetic filters
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            let body_sender_final = body_sender.clone();
            let _ = handle.block_on(async {
                Self::inject_cosmetics(
                    url,
                    ids,
                    classes,
                    adblock_requester,
                    statistics,
                    body_sender_final,
                )
                .await
            });
        }
    }

    async fn inject_cosmetics(
        url: String,
        ids: HashSet<String>,
        classes: HashSet<String>,
        adblock_requester: AdblockRequester,
        statistics: Statistics,
        body_sender: Sender<Result<Frame<Bytes>, hyper::Error>>,
    ) {
        let mut response_has_been_modified = false;

        let blocker_result = adblock_requester
            .get_cosmetic_response(
                url,
                Vec::from_iter(ids.into_iter()),
                Vec::from_iter(classes.into_iter()),
            )
            .await;

        let mut to_append_to_response = format!(
            r#"
<!-- privaxy proxy -->
<style>{hidden_selectors}
{style_selectors}
</style>
<!-- privaxy proxy -->"#,
            hidden_selectors = {
                // We insert one `display: none !important;` entry per selector
                // as otherwise, a single malformed selector would be breaking blocking.
                blocker_result
                    .hidden_selectors
                    .into_iter()
                    .map(|selector| {
                        format!(
                            r#"
                            {}
                            {{
                                display: none !important;
                            }}
                    "#,
                            selector
                        )
                    })
                    .collect::<String>()
            },
            style_selectors = {
                let style_selectors = blocker_result.style_selectors;

                if !style_selectors.is_empty() {
                    response_has_been_modified = true
                }

                style_selectors
                    .into_iter()
                    .map(|(selector, content)| {
                        format!(
                            "{selector} {{ {content} }}",
                            selector = selector,
                            content = content.join(";")
                        )
                    })
                    .collect::<String>()
            }
        );

        if let Some(injected_script) = blocker_result.injected_script {
            response_has_been_modified = true;

            write!(
                to_append_to_response,
                r#"
<!-- Privaxy proxy -->
<script type="application/javascript">{}</script>
<!-- privaxy proxy -->
"#,
                injected_script
            )
            .unwrap();
        }

        if response_has_been_modified {
            statistics.increment_modified_responses();
        }

        let _ = body_sender
            .send(Ok(Frame::data(Bytes::from(to_append_to_response))))
            .await;
    }
}
