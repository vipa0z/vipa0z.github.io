(function($){
  $(".content").each(function(i){
    $(this).find("img").each(function(){
      var $img=$(this);
      if(!$img.hasClass("nofancybox")){
        var $entry=$img.closest('.entry[data-post-url]');
        if($entry.length){
          var postUrl=$entry.data('post-url');
          if($img.parent('a').length===0){
            var alt=this.alt;
            if(alt){
              $img.wrap('<a href="'+postUrl+'" title="'+alt+'" class="index-post-link" />');
            }else{
              $img.wrap('<a href="'+postUrl+'" class="index-post-link" />');
            }
          }
        }else{
          var alt=this.alt;
          if(alt){
            $img.wrap('<a href="'+this.src+'" title="'+alt+'" class="fancybox" rel="gallery'+i+'" />');
          }else{
            $img.wrap('<a href="'+this.src+'" class="fancybox" rel="gallery'+i+'" />');
          }
        }
      }
    });
  });

  var play=function(parent,item,callback){var width=parent.width();item.imagesLoaded(function(){var _this=this[0],nWidth=_this.naturalWidth,nHeight=_this.naturalHeight;callback();this.animate({opacity:1},500);parent.animate({height:width*nHeight/nWidth},500);});};
  $(".gallery").each(function(){var $this=$(this),current=0,photoset=$this.children(".photoset").children(),all=photoset.length,loading=true;play($this,photoset.eq(0),function(){loading=false;});$this.on("click",".prev",function(){if(!loading){var next=(current-1)%all;loading=true;play($this,photoset.eq(next),function(){photoset.eq(current).animate({opacity:0},500);loading=false;current=next;});}}).on("click",".next",function(){if(!loading){var next=(current+1)%all;loading=true;play($this,photoset.eq(next),function(){photoset.eq(current).animate({opacity:0},500);loading=false;current=next;});}});});
})(jQuery);