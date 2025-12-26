var fs = require('fs');
var path = require('path');

hexo.extend.helper.register('list_images_in_dir', function (relativePath) {
    var imgDir = path.join(process.cwd(), relativePath);
    var images = [];
    try {
        if (fs.existsSync(imgDir)) {
            images = fs.readdirSync(imgDir).filter(function (file) {
                var ext = path.extname(file).toLowerCase();
                return ['.jpg', '.jpeg', '.png', '.gif', '.avif', '.webp'].indexOf(ext) !== -1;
            });
        }
    } catch (e) {
        console.error("Error listing images in " + imgDir + ": " + e);
    }
    return images;
});
