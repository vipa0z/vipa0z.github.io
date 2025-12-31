// file with custom additions vipa0z)

$(document).ready(function () {
    $(window).scroll(function () {
        var scrollt = document.documentElement.scrollTop + document.body.scrollTop;
        if (scrollt > 200) {
            $("#gotop").fadeIn(400);
            if ($(window).width() >= 1200) {
                $(".navbar").stop().fadeTo(400, 0.2);
            }
        } else {
            $("#gotop").fadeOut(400);
            if ($(window).width() >= 1200) {
                $(".navbar").stop().fadeTo(400, 1);
            }
        }
    });

    $("#gotop").click(function () {
        $("html,body").animate({ scrollTop: "0px" }, 200);
    });

    $(".navbar").mouseenter(function () {
        $(".navbar").fadeTo(100, 1);
    });

    $(".navbar").mouseleave(function () {
        var scrollt = document.documentElement.scrollTop + document.body.scrollTop;
        if (scrollt > 200) {
            $(".navbar").fadeTo(100, 0.2);
        }
    });

    // Add copy button to code blocks - BUTTON ABOVE CODE
    $('figure.highlight').each(function () {
        var text = $(this).html();

        // List of pentesting tools
        var tools = ['python3', 'gobuster', 'ffuf', 'kr', 'python2', 'python', 'netexec', 'impacket-smbserver', 'ffuf', 'sqlmap', 'nmap', 'metasploit', 'burpsuite', 'hashcat', 'john', 'hydra', 'aircrack-ng', 'wireshark', 'nikto', 'masscan'];

        tools.forEach(function (tool) {
            var regex = new RegExp('\\b' + tool + '\\b', 'gi');
            text = text.replace(regex, '<span class="pentesting-tool">' + tool + '</span>');
        });

        $(this).html(text);

        var block = $(this);
        var codeCell = block.find('td.code');
        if (!codeCell.length) return;

        var btn = $('<button class="copy-btn" type="button"></button>');
        var svgIcon = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" fill="#fff" fill-opacity="0.15" stroke="#fff" stroke-width="2"/><rect x="3" y="3" width="13" height="13" rx="2" fill="#fff" fill-opacity="0.25" stroke="#fff" stroke-width="2"/></svg>';

        btn.html(svgIcon);
        btn.css({
            'display': 'block',
            'background': 'rgba(0,0,0,0.7)',
            'border': 'none',
            'borderRadius': '4px',
            'padding': '8px',
            'cursor': 'pointer',
            'transition': 'background 0.2s',
            'position': 'absolute',
            'top': '8px',
            'right': '8px',
            'zIndex': '1000',
            'width': '32px',
            'height': '32px'
        });

        btn.attr('title', 'Copy code');
        btn.attr('aria-label', 'Copy code to clipboard');

        btn.on('click', function (e) {
            e.preventDefault();
            e.stopPropagation();

            var code = codeCell.find('pre');
            if (code.length) {
                var text = code.text();

                // Remove leading $ signs and trim whitespace
                text = text.replace(/^\s*\$\s*/gm, '').trim();

                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).then(function () {
                        showSuccess();
                    }).catch(function () {
                        fallbackCopy();
                    });
                } else {
                    fallbackCopy();
                }
            }

            function showSuccess() {
                btn.css({
                    'background': 'rgba(76, 175, 80, 0.9)',
                    'opacity': '0.7'
                });
                setTimeout(function () {
                    btn.css({
                        'background': 'rgba(0,0,0,0.7)',
                        'opacity': '1'
                    });
                }, 1500);
            }

            function fallbackCopy() {
                var textarea = $('<textarea>').val(text).appendTo('body');
                textarea[0].select();
                try {
                    document.execCommand('copy');
                    showSuccess();
                } catch (err) {
                    console.error('Copy failed:', err);
                }
                textarea.remove();
            }
        });

        block.append(btn);
    });

    replaceMeta();
    $(window).resize(function () {
        replaceMeta();
    });

    // Wrap images in a link to the post (only on index/archive pages, not on individual posts)
    if ($('.page.overview').length > 0 || $('.archive').length > 0) {
        $('.mypage img').each(function () {
            var $img = $(this);
            // Skip if already wrapped in a link
            if ($img.parent('a').length > 0) return;

            var postUrl = $img.closest('.row').find('.title a').attr('href');
            if (postUrl) {
                $img.wrap($('<a></a>').attr('href', postUrl));
            }
        });
    }
});
replaceMeta = function () {
    if ($(window).width() < 980) {
        if ($("#side_meta #post_meta").length > 0) {
            $("#post_meta").appendTo("#top_meta");
        }
        if ($("#sidebar #site_search").length > 0) {
            $("#site_search").appendTo("#top_search");
            $("#site_search #st-search-input").css("width", "95%");
        }
    } else {
        if ($("#top_meta #post_meta").length > 0) {
            $("#post_meta").appendTo("#side_meta");
        }
        if ($("#top_search #site_search").length > 0) {
            $("#site_search").prependTo("#sidebar");
            $("#site_search #st-search-input").css("width", "85%");
        }
    }
};