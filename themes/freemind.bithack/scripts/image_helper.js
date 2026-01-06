var fs = require('fs');
var path = require('path');


hexo.extend.helper.register('get_random_image', function (subdir) {
    var baseDir = hexo.source_dir || path.join(process.cwd(), 'source');
    var imagesDir = path.join(baseDir, 'images', subdir);
    var selectedImage = '';

    try {
        if (fs.existsSync(imagesDir)) {
            var files = fs.readdirSync(imagesDir).filter(function (file) {
                if (file.startsWith('.')) return false;
                var ext = path.extname(file).toLowerCase();
                var validExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'];
                return validExts.indexOf(ext) !== -1 && file !== 'cpts+back.png';
            });

            if (files.length > 0) {
                var randomIndex = Math.floor(Math.random() * files.length);
                selectedImage = files[randomIndex];
            }
        }
    } catch (e) {
        console.error('[ImageHelper] Error getting image from ' + subdir + ':', e);
    }

    return selectedImage;
});

hexo.extend.helper.register('get_all_images', function (subdir) {
    var baseDir = hexo.source_dir || path.join(process.cwd(), 'source');
    var imagesDir = path.join(baseDir, 'images', subdir);
    var allImages = [];

    try {
        if (fs.existsSync(imagesDir)) {
            allImages = fs.readdirSync(imagesDir).filter(function (file) {
                if (file.startsWith('.')) return false;
                var ext = path.extname(file).toLowerCase();
                var validExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'];
                return validExts.indexOf(ext) !== -1; // Removed cpts+back.png check as we might want it in general or filter it later if needed, but for now I'll stick to logic close to random if desired, but user didn't specify excluding it here. Actually, to be safe and consistent with previous behavior, let's exclude it if it was excluded before.
            }).filter(function (file) {
                return file !== 'cpts+back.png';
            });
        }
    } catch (e) {
        console.error('[ImageHelper] Error getting images from ' + subdir + ':', e);
    }

    return allImages;
});
